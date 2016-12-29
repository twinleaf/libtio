// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <tio/io.h>
#include <tio/data.h>
#include <tio/rpc.h>

#include <string>
#include <sstream>
#include <fstream>
#include <map>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>

const tl_data_stream_desc_header *get_streamdesc(const tl_rpc_reply_packet *rep)
{
  size_t size = rep->payload_size();
  if (size < sizeof(tl_data_stream_desc_header))
    return nullptr;
  return rep->payload_start<tl_data_stream_desc_header>();
}

std::string get_streamname(const tl_rpc_reply_packet *rep)
{
  std::string ret;
  size_t size = rep->payload_size();
  if (size > sizeof(tl_data_stream_desc_header)) {
    ret = std::string(rep->payload_start<char>() +
                      sizeof(tl_data_stream_desc_header),
                      size - sizeof(tl_data_stream_desc_header));
  }
  return ret;
}

std::string get_streamname(const tl_data_stream_desc_packet *desc)
{
  return std::string(desc->name, desc->hdr.payload_size -
                     sizeof(tl_data_stream_desc_header));
}

class dstream_key {
 public:
  dstream_key() = default;
  dstream_key(const tl_data_stream_packet *dsp):
    dstream_key(dsp->hdr.stream_id(), &dsp->hdr) {}
  dstream_key(const tl_data_stream_desc_packet *dsdp):
    dstream_key(dsdp->desc.stream_id, &dsdp->hdr) {}
  dstream_key(const tl_rpc_reply_packet *rep):
    dstream_key(get_streamdesc(rep)->stream_id, &rep->hdr) {}

  bool operator<(const dstream_key &k) const {
    if (stream_id != k.stream_id)
      return stream_id < k.stream_id;
    if (routing_size != k.routing_size)
      return routing_size < k.routing_size;
    return (memcmp(routing, k.routing, routing_size) < 0);
  }

  bool operator==(const dstream_key &k) const {
    return (stream_id == k.stream_id) && (routing_size == k.routing_size) &&
      (memcmp(routing, k.routing, routing_size) == 0);
  }

  bool operator!=(const dstream_key &k) const { return !(*this == k); }

 private:
  friend class dstream_writer;

  dstream_key(int id, const tl_packet_header *hdr):
    stream_id(id), routing_size(hdr->routing_size) {
    memcpy(routing, hdr->routing_data(), routing_size);
  }

  int stream_id = -1;
  size_t routing_size = 0;
  uint8_t routing[TL_PACKET_MAX_ROUTING_SIZE];
};

class write_filedesc {
 public:
  write_filedesc() = default;
  write_filedesc(const write_filedesc&) = delete;
  write_filedesc(write_filedesc&&) = delete;

  ~write_filedesc() { if (is_open() ) close(); }

  void open(const std::string &path);
  void close() { ::close(fd); fd = -1; }
  void write(const void *buf, size_t size) { ::write(fd, buf, size); }
  bool is_open() const { return fd >= 0; }

 private:
  int fd = -1;
  bool try_open(const std::string &path);
};

void write_filedesc::open(const std::string &path)
{
  if (is_open())
    close();

  char repeat_counter[32];
  repeat_counter[0] = '\0';

  for (size_t rep = 1; fd < 0; rep++) {
    std::string trypath = path + repeat_counter;
    printf("Trying to open: %s\n", trypath.c_str());
    fd = ::open(trypath.c_str(), O_CREAT | O_WRONLY | O_EXCL, 0666);
    snprintf(repeat_counter, sizeof(repeat_counter), ".%zu", rep);
  }
}

class dstream_writer {
 public:
  dstream_writer() = default;
  void process_desc(const tl_data_stream_desc_header *desc,
                    const std::string &name,
                    const dstream_key &key);
  bool process_data(const tl_data_stream_packet *data);

 private:
  tl_data_stream_desc_header desc;

  int64_t last_sample = -1;

  write_filedesc out;
};

int main(int argc, char *argv[])
{
  if (argc < 2)
    return 1;

  std::map<uint16_t, dstream_key> rpc_to_stream;
  std::map<dstream_key, uint16_t> stream_to_rpc;
  std::map<dstream_key, dstream_writer> streams;

  int fd = tlopen(argv[1], O_CLOEXEC, NULL);

  for (;;) {
    tl_packet pkt;
    int ret = tlrecv(fd, &pkt, sizeof(pkt));
    if (ret != 0)
      break;

    timespec recv_time;
    clock_gettime(CLOCK_MONOTONIC, &recv_time);

    int stream = tl_packet_stream_id(&pkt.hdr);

    if (stream >= 0) {
      tl_data_stream_packet *dsp =
        reinterpret_cast<tl_data_stream_packet*>(&pkt);
      dstream_key key(dsp);

      if (!streams[key].process_data(dsp) && !stream_to_rpc.count(key)) {
        // packet was buffered, stream is missing description.
        // must request it.
        uint8_t stream_id = stream;
        uint16_t req_id = 0;
        tl_rpc_request_packet req;
        if (!rpc_to_stream.empty())
          req_id = rpc_to_stream.rbegin()->first + 1;
        if (tl_rpc_request_by_name(&req, req_id, "dstream.desc", &stream_id,
                                   sizeof(stream_id)) != 0) {
          return 1;
        }
        if (tlsend(fd, &req) != 0) {
          return 1;
        }
        rpc_to_stream[req_id] = key;
        stream_to_rpc[key] = req_id;
      }
      continue;
    }

    // not a stream packet
    if (pkt.hdr.type == TL_PTYPE_STREAMDESC) {
      tl_data_stream_desc_packet *desc =
        reinterpret_cast<tl_data_stream_desc_packet*>(&pkt);
      dstream_key key(desc);
      streams[key].process_desc(&desc->desc, get_streamname(desc), key);
    } else if (pkt.hdr.type == TL_PTYPE_RPC_REP) {
      tl_rpc_reply_packet *rep = reinterpret_cast<tl_rpc_reply_packet*>(&pkt);
      auto it = rpc_to_stream.find(rep->rep.req_id);
      if (it != rpc_to_stream.end()) {
        const tl_data_stream_desc_header *desc = get_streamdesc(rep);
        if (desc) {
          // check that the reply comes from the stream we are expecting
          dstream_key key(rep);
          if (key == it->second) {
            streams[key].process_desc(desc, get_streamname(rep), key);
          } else {
            // What is this?
          }
        } else {
          // What is this?
        }
        stream_to_rpc.erase(it->second);
        rpc_to_stream.erase(it);
      } else {
        // what is this??
      }
    } else if (pkt.hdr.type == TL_PTYPE_RPC_ERROR) {
      tl_rpc_error_packet *err = reinterpret_cast<tl_rpc_error_packet*>(&pkt);
      auto it = rpc_to_stream.find(err->err.req_id);
      if (it != rpc_to_stream.end()) {
        stream_to_rpc.erase(it->second);
        rpc_to_stream.erase(it);
      } else {
        // what is this??
      }
    } else {
      // something we don't care about, like a log message
    }
  }

  int ret = (errno != EINTR);
  tlclose(fd);
  return ret;
}

void dstream_writer::process_desc(const tl_data_stream_desc_header *desc_,
                                  const std::string &name,
                                  const dstream_key &key)
{
  tl_data_stream_desc_header tmp = *desc_;
  tmp.sample_counter = 0;
  tmp.flags = 0;

  if (out.is_open() && ((memcmp(&tmp, &desc, sizeof(desc)) != 0) ||
                        (desc_->flags & TL_DATA_STREAM_STOPPED) ||
                        (int64_t(desc_->sample_counter) < last_sample))) {
    out.close();
  }

  if (!out.is_open() && !(desc_->flags & TL_DATA_STREAM_STOPPED)) {
    // make filename for recording this stream
    std::ostringstream ss;
    ss << "dstream";
    for (size_t i = key.routing_size; i > 0; i--)
      ss << "_" << int(key.routing[i-1]);
    ss << "." << int(tmp.stream_id);
    if (name.length() > 0)
      ss << "." << name;
    ss << "." << int(tmp.restart_id);
    ss << "." << time(NULL);

    out.open(ss.str());

    last_sample = desc_->sample_counter;
    if (desc_->flags & TL_DATA_STREAM_FIRST)
      last_sample--;

    desc = tmp;

    tl_packet_header file_header;
    file_header.type = TL_PTYPE_STREAMDESC;
    file_header.routing_size = 0;
    file_header.payload_size = sizeof(desc) + name.length();

    out.write(&file_header, sizeof(tl_packet_header));
    out.write(&desc, sizeof(desc));
    out.write(name.c_str(), name.length());
  }
}

bool dstream_writer::process_data(const tl_data_stream_packet *data)
{
  if (!out.is_open())
    return false;

  // check that this packet makes sense given what we know about the
  // stream. if so, record it. if not, close the stream and indicate that
  // we need to update the description.

  // make sure that the data payload is a multiple of the sample size.
  size_t sample_size = tl_data_type_size(desc.type) * desc.channels;
  size_t data_size = data->hdr.payload_size - sizeof(data->start_sample);
  if ((data_size % sample_size) != 0) {
    out.close();
    return false;
  }

  // and that looking at the modular sample number we are some number of
  // samples ahead
  int32_t delta = data->start_sample - uint32_t(last_sample);
  if ((delta <= 0) || (delta > 1000000)) {
    out.close();
    return false;
  }

  // packet looks legit. update last sample and write out
  last_sample += delta;
  tl_packet_header hdr = data->hdr;
  hdr.routing_size = 0;
  out.write(&hdr, sizeof(hdr));
  out.write(data->hdr.payload_data(), hdr.payload_size);

  return true;
}
