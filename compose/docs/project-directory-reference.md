# Compose 5.6.1 project-directory reference

Daemon-free `docker compose -f compose.yaml config --format json`, using
`project_directory: parts`, produced the same output for both
`path: parts/app.yaml` and `path: parts/nested/app.yaml`. The only substitution
below is `<ROOT>` for the absolute fixture directory. The project name was
`include-probe-2297735`.

```json
{
  "configs": {
    "cfg": {
      "name": "include-probe-2297735_cfg",
      "file": "<ROOT>/parts/config.txt"
    }
  },
  "name": "include-probe-2297735",
  "networks": {
    "default": {
      "name": "include-probe-2297735_default",
      "ipam": {}
    }
  },
  "secrets": {
    "sec": {
      "name": "include-probe-2297735_sec",
      "file": "<ROOT>/parts/secret.txt"
    }
  },
  "services": {
    "app": {
      "command": null,
      "configs": [
        {
          "source": "cfg"
        }
      ],
      "entrypoint": null,
      "environment": {
        "VALUE": "from_env"
      },
      "image": "alpine",
      "networks": {
        "default": null
      },
      "secrets": [
        {
          "source": "sec",
          "target": "/run/secrets/sec"
        }
      ],
      "volumes": [
        {
          "type": "bind",
          "source": "<ROOT>/parts/bind",
          "target": "/mnt",
          "bind": {}
        }
      ],
      "build": {
        "context": "<ROOT>/parts/ctx",
        "dockerfile": "Dockerfile"
      }
    }
  }
}
```

With `path: parts/nested/*.yaml` and `project_directory: parts`, the same CLI
reported `open <ROOT>/parts/nested/*.yaml: no such file or directory`: this
version treated the wildcard literally. This loader explicitly refuses that
combination.
