# Numeric address claim audit

An offline static audit of documentation claims against Python source. It reads the root README and Markdown under directories named `docs`, excluding fenced blocks. Inline code counts. It parses source without executing it and reports discrepancies.

## Usage

```sh
ip-address-validation-claim-audit audit .
ip-address-validation-claim-audit audit . --json --verbose --ignore vendor --fail-on medium
ip-address-validation-claim-audit --version
python3 -m ip_address_validation_claim_audit audit .
```

The default threshold is high. Exit status is 0 when no finding reaches the threshold, 2 when one does, and 1 for usage or I/O errors. Test-only evidence produces a medium finding; production evidence contradicting a denial produces a high finding. A positive claim without production evidence produces a high finding unless evidence exists only in tests.

```text
documented-ip-address-validation-claim-false
documented-no-ip-address-validation-claim-false
```

## Differentiation

This audit concerns well-formed numeric addresses. Other families cover generic input validation, authentication and one-time ownership confirmation, password verification, password hashing, password generation, PDF encryption, email sending, SMS sending, document extraction, barcode and QR decoding, email validation, phone-number validation, password strength, JSON Schema validation, URL validation, and domain validation. JSON decoding, regex matching, URL parsing, and network fetching are distinct operations.

Other claim families include spreadsheet reading and generation, word-document reading and generation, presentation reading and generation, PDF extraction, generation, merging, splitting, rotation, form-filling, watermarking, redaction, compression and annotation, table extraction, OCR, e-signature, payment processing, screen recording, video generation, QR and barcode generation, barcode scanning, audio mixing, generation and editing, source separation, speech recognition, text-to-speech, noise suppression, music generation and transcription.

## Limitations

- This phrase may describe a remote policy lookup instead of implemented checking:

  ```text
  validate ip address
  ```

- This phrase may describe a manual runbook step instead of implemented checking:

  ```text
  check ip address
  ```

- This phrase may describe a roadmap feature instead of implemented checking:

  ```text
  ip address validation
  ```

- This phrase may describe a hosted page instead of implemented checking:

  ```text
  ip address validator
  ```

- This phrase may describe reader advice instead of implemented checking:

  ```text
  valid ip address
  ```

- This phrase may describe a successful lookup instead of implemented checking:

  ```text
  ip address is valid
  ```

- This phrase may describe a reachability test instead of implemented checking:

  ```text
  ip address check
  ```

- This phrase may describe a ping service instead of implemented checking:

  ```text
  ip address checker
  ```

- This phrase may describe a documented pattern without code instead of implemented checking:

  ```text
  ip address format check
  ```

- This phrase may describe an ownership confirmation instead of implemented checking:

  ```text
  verify ip address
  ```

- This phrase may describe a length rule alone instead of implemented checking:

  ```text
  detect invalid ip address
  ```

- This phrase may describe a theoretical discussion instead of implemented checking:

  ```text
  ip address well formed
  ```

- This phrase may describe a generated value instead of implemented checking:

  ```text
  is valid ip address
  ```

- This phrase may describe a specification section instead of implemented checking:

  ```text
  ip address validity
  ```

- A call shape counts even when never executed.
- A variable chain holding a library can be missed.
- A library import without a call is not evidence.
- Roadmap prose is still a claim.
- Changelog prose is still a claim.
- TODO prose is still a claim.
- Denials outside the listed phrases can be missed.
- A top-level changelog outside the selected documents is invisible.
- A route must occur in one module.
- Locally defined route names shadow imports.
- Dead code counts.
- External subprocess tools do not count.
- Generic input checks alone do not count.
- Email checks alone do not count.
- Phone checks alone do not count.
- Extraction alone does not count.
- A locally defined generic name is shadowed.
- Generic calls through untracked alias chains are missed.
- Only exact phrases are matched, not meaning.
- Implementations in other languages are invisible.
- Runtime-only routes are invisible; source is not executed and no network is used.
- A pydantic annotation alone does not count.
- An ipaddress annotation alone does not count.
- A socket conversion alone does not count.
- A DNS lookup alone does not count.
- A regex match alone does not count.
- A domain check alone does not count.
- A Django factory alone does not count.
- The Django internal IPv6 helper alone does not count.
- An address property read alone does not count.
