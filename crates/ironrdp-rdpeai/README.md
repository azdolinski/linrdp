# IronRDP AUDIO_INPUT (MS-RDPEAI)

[MS-RDPEAI][1] implementation over Dynamic Virtual Channels [MS-RDPEDYC][2].

This library includes:

- AUDIO_INPUT PDU parse/serialize (`MSG_SNDIN_*`)
- Dynamic virtual channel client processor (the side that captures)
- Capture backend trait for feeding PCM packets upstream
- Dynamic virtual channel server processor (the side that records): it
  drives the initialization sequence and hands the client's audio to a
  handler

Minimum supported codec: `WAVE_FORMAT_PCM` (0x0001).

[1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeai/2eb8be0c-4f17-418b-9911-edb8d2ffcde5
[2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc/3bd53020-9b64-4c9a-97fc-90a79e7e1e06
