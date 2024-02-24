import re
from argparse import ArgumentParser, ArgumentTypeError
from email import message_from_binary_file, policy
from email.utils import parsedate_to_datetime, parseaddr
from pathlib import Path
from typing import List
from os.path import basename
from shutil import copyfile


def extract_attachments(file: Path, destination: Path) -> None:
    print(f'PROCESSING FILE "{file}"')
    error_path = destination / 'err'
    file_out_base = basename(file)
    try:
        with (file.open(mode='rb') as f):
            email_message = message_from_binary_file(f, policy=policy.default)
            save_policy = email_message.policy.clone(cte_type='8bit', utf8=True)
            email_subject = email_message.get('Subject')
            email_subject = "NoSubject" if len(email_subject) == 0 else email_subject
            email_from = email_message.get('From')
            from_addr = parseaddr(email_from)[1]
            email_date = email_message.get('Date')
            file_date = parsedate_to_datetime(email_date).isoformat()
            base_path = destination / sanitize_foldername(file_date + '-' + from_addr)
            base_path.mkdir(exist_ok=True)
            text_parts = [item for item in email_message.walk() if item.get_content_type().startswith('text/') and not item.get_filename()]
            for text_part in text_parts:
                payload = text_part.get_payload(decode=True)
                charset = text_part.get_content_charset()
                charset = 'gb18030' if charset == 'gb2312' else charset # Sometimes text with charset gb2312 includes characters which is in fact from charset gb18030.
                payload_decoded = payload.decode(encoding=charset)
                text_part.set_payload(payload_decoded.encode(encoding='utf-8'))
                try:
                    text_part.replace_header('content-transfer-encoding', '8bit')
                except:
                    text_part.add_header('content-transfer-encoding', '8bit')
                text_part.set_charset('utf-8')
            # include inline attachments
            inline_attach = [item for item in email_message.walk() if item.get_filename()]
            if not inline_attach:
                print('>> No inline/attachments found.')
                email_cleaned = email_message.as_bytes(policy=save_policy)
                save_message(base_path / sanitize_foldername(email_subject + ".eml"), email_cleaned)
                return
            attach_no = 0
            for file_inline_attach in inline_attach:
                filename_save = file_inline_attach.get_filename()
                print(f'>> Inline/Attachment found: {filename_save}')
                attach_no += 1
                filepath = base_path / sanitize_foldername("%03d" % attach_no + ' ' + filename_save)
                payload = file_inline_attach.get_payload(decode=True)
                save_attachment(filepath, payload)
                file_inline_attach.set_payload("")
            email_cleaned = email_message.as_bytes(policy=save_policy)
            save_message(base_path / sanitize_foldername(email_subject + ".eml"), email_cleaned)
    except Exception as X:
        print('=====', type(X), ': ', X)
        error_path.mkdir(exist_ok=True)
        error_filepath = error_path / file_out_base
        print('Copy', file, 'to', error_filepath)
        copyfile(file, error_filepath)


def sanitize_foldername(name: str) -> str:
    illegal_chars = r'[/\\|:<>=?!*"~#&\']'
    return re.sub(illegal_chars, '_', name)


def save_attachment(file: Path, payload: bytes) -> None:
    with file.open('wb') as f:
        print(f'>> Saving attachment to "{file}"')
        f.write(payload)


def save_message(file: Path, message: bytes) -> None:
    with file.open('wb') as f:
        print(f'>> Saving cleaned email to "{file}"')
        f.write(message)


def get_eml_files_from(path: Path, recursively: bool = False) -> List[Path]:
    if recursively:
        return list(path.rglob('*.eml'))
    return list(path.glob('*.eml'))


def check_file(arg_value: str) -> Path:
    file = Path(arg_value)
    if file.is_file() and file.suffix == '.eml':
        return file
    raise ArgumentTypeError(f'"{file}" is not a valid EML file.')


def check_path(arg_value: str) -> Path:
    path = Path(arg_value)
    if path.is_dir():
        return path
    raise ArgumentTypeError(f'"{path}" is not a valid directory.')


def get_argument_parser():
    parser = ArgumentParser(
        usage='%(prog)s [OPTIONS]',
        description='Extracts attachments from .eml files'
    )
    # force the use of --source or --files, not both
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        '-s',
        '--source',
        type=check_path,
        default=Path.cwd(),
        metavar='PATH',
        help='the directory containing the .eml files to extract attachments (default: current working directory)'
    )
    parser.add_argument(
        '-r',
        '--recursive',
        action='store_true',
        help='allow recursive search for .eml files under SOURCE directory'
    )
    source_group.add_argument(
        '-f',
        '--files',
        nargs='+',
        type=check_file,
        metavar='FILE',
        help='specify a .eml file or a list of .eml files to extract attachments'
    )
    parser.add_argument(
        '-d',
        '--destination',
        type=check_path,
        default=Path.cwd(),
        metavar='PATH',
        help='the directory to extract attachments to (default: current working directory)'
    )
    return parser


def parse_arguments():
    parser = get_argument_parser()
    return parser.parse_args()


def main():
    args = parse_arguments()

    eml_files = args.files or get_eml_files_from(args.source, args.recursive)
    if not eml_files:
        print(f'No EML files found!')

    destination = args.destination
    for file in eml_files:
        extract_attachments(file, destination)
    print('Done.')


if __name__ == '__main__':
    main()
