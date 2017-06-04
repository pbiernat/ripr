
# Instead of GUI, just prompt on the command line
class cli_ui:
    def yes_no_box(self, question):
        while True:
            response = raw_input("{} (Y/N)".format(question))
            if len(response) < 1 or response[0] not in ['y','n','N','Y']:
                continue

            if response[0].lower() == 'y':
                return True
            else:
                return False

    def update_table(self, newTable):
        #TODO: Not showing a table for now
        pass

    def text_input_box(self, promptText):
        return raw_input(promptText + "? ").strip()

    def impCallsOptions(self):
        options = ["nop", "hook", "cancel"]

        print "Code contains calls to imported functions. How should this be handled?",
        while True:
            selection = raw_input("({})?".format(", ".join(options))).strip()
            if selection in options:
                return selection

