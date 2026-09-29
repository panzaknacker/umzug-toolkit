/* local quarantine heuristics, not a vendor signature database.
 * a match needs investigation; a non-match is never evidence that a file is safe.
 * verify the toolkit release independently, hash these exact bytes on the
 * trusted analysis host and pin that SHA-256 in the scanner policy.
 */

rule UMZUG_Private_Key_Material
{
    meta:
        description = "Unencrypted PEM or OpenSSH private-key material"
        confidence = "high"
        response = "block and inspect without exposing the key"

    strings:
        $pkcs8 = "-----BEGIN PRIVATE KEY-----" ascii
        $pkcs8_enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----" ascii
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii
        $dsa = "-----BEGIN DSA PRIVATE KEY-----" ascii
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii

    condition:
        filesize < 32MB and any of them
}

rule UMZUG_Shell_Download_Execute_Chain
{
    meta:
        description = "Shell script combines a downloader with immediate execution"
        confidence = "medium-high"
        response = "block; reconstruct the dependency from a verified offline source"

    strings:
        $shebang_sh = "#!/bin/sh" ascii
        $shebang_bash = "#!/bin/bash" ascii
        $shebang_env_bash = "#!/usr/bin/env bash" ascii
        $download_curl = "curl " ascii nocase
        $download_wget = "wget " ascii nocase
        $execute_pipe_sh = "| sh" ascii
        $execute_pipe_bash = "| bash" ascii
        $execute_chmod = "chmod +x" ascii
        $execute_tmp = "/tmp/" ascii

    condition:
        filesize < 2MB and
        1 of ($shebang*) and
        1 of ($download*) and
        2 of ($execute*)
}

rule UMZUG_Obfuscated_Shell_Decode_Execute
{
    meta:
        description = "Shell script decodes base64 data and executes the result"
        confidence = "medium-high"
        response = "block and deobfuscate in a disposable, networkless analysis VM"

    strings:
        $shebang_sh = "#!/bin/sh" ascii
        $shebang_bash = "#!/bin/bash" ascii
        $shebang_env_bash = "#!/usr/bin/env bash" ascii
        $decode_short = "base64 -d" ascii nocase
        $decode_long = "base64 --decode" ascii nocase
        $execute_eval = "eval " ascii
        $execute_pipe_sh = "| sh" ascii
        $execute_pipe_bash = "| bash" ascii

    condition:
        filesize < 2MB and
        1 of ($shebang*) and
        1 of ($decode*) and
        1 of ($execute*)
}

rule UMZUG_PHP_Eval_Webshell_Primitives
{
    meta:
        description = "PHP combines attacker-controlled request data, decoding, and execution"
        confidence = "medium-high"
        response = "block and inspect the complete application and deployment history"

    strings:
        $php = "<?php" ascii nocase
        $input_get = "$_GET[" ascii
        $input_post = "$_POST[" ascii
        $input_request = "$_REQUEST[" ascii
        $decode_b64 = "base64_decode(" ascii nocase
        $decode_gzinflate = "gzinflate(" ascii nocase
        $exec_eval = "eval(" ascii nocase
        $exec_assert = "assert(" ascii nocase
        $exec_system = "system(" ascii nocase
        $exec_shell = "shell_exec(" ascii nocase

    condition:
        filesize < 4MB and
        $php and
        1 of ($input*) and
        1 of ($decode*) and
        1 of ($exec*)
}

rule UMZUG_ELF_Reverse_Shell_Indicators
{
    meta:
        description = "ELF contains a compact set of reverse-shell primitives"
        confidence = "medium-high"
        response = "block; never execute the binary on the target"

    strings:
        $net_connect = "connect" ascii
        $net_dup2 = "dup2" ascii
        $shell_bin_sh = "/bin/sh" ascii
        $shell_bin_bash = "/bin/bash" ascii
        $shell_dev_tcp = "/dev/tcp/" ascii

    condition:
        filesize < 64MB and
        uint32(0) == 0x464c457f and
        all of ($net*) and
        1 of ($shell*)
}

rule UMZUG_Systemd_Downloader_Persistence
{
    meta:
        description = "systemd unit launches a downloader or download-execute shell"
        confidence = "medium-high"
        response = "block; rebuild the unit manually from a reviewed declaration"

    strings:
        $unit = "[Unit]" ascii
        $service = "[Service]" ascii
        $exec = "ExecStart=" ascii
        $curl = "curl " ascii nocase
        $wget = "wget " ascii nocase
        $dev_tcp = "/dev/tcp/" ascii

    condition:
        filesize < 1MB and
        $unit and $service and $exec and
        1 of ($curl, $wget, $dev_tcp)
}

rule UMZUG_SSH_Forced_Command_Authorization
{
    meta:
        description = "SSH public-key authorization embeds a forced command"
        confidence = "high for active authorization material"
        response = "block; recreate authorization explicitly on the target if truly required"

    strings:
        $forced = "command=\"" ascii
        $ed25519 = "ssh-ed25519 " ascii
        $rsa = "ssh-rsa " ascii
        $ecdsa = "ecdsa-sha2-" ascii

    condition:
        filesize < 1MB and
        $forced and
        1 of ($ed25519, $rsa, $ecdsa)
}
