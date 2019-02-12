from analyzer.analyzer import APK

class {{user_apk_class}}:
    def __init__(self):
        self.file_path = '/where/your/targeted/apk/is/here.apk'
        self.orig_apk = APK('{{user_apk_name}}', self.file_path)
        self.fuzz_apk, self.func_map = self.orig_apk.get_custom_app()
