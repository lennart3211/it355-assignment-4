from app.commands.BlabberCommand import BlabberCommand
from typing import override
import sys
import logging

class IgnoreCommand(BlabberCommand):
    logger = logging.getLogger("VeraDemo:IgnoreCommand")

    cursor = None
    username = None

    def __init__(self, cursor, username):
        super()
        self.cursor = cursor
        self.username = username

    @override
    def execute(self, blabberUsername):
        sqlQuery = "DELETE FROM listeners WHERE blabber=? AND listener=?"
        self.logger.info(sqlQuery)
        try:
            self.cursor.execute(sqlQuery, (blabberUsername, self.username))

            sqlQuery = "SELECT blab_name FROM users WHERE username = ?"
            self.logger.info(sqlQuery)
            self.cursor.execute(sqlQuery, (blabberUsername,))
            result = self.cursor.fetchone()

            event = self.username + " is now ignoring " + blabberUsername + " (" + result[0] + ")"
            sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)"
            self.logger.info(sqlQuery)
            self.cursor.execute(sqlQuery, (self.username, event))

        except:

            # TODO: Implement exceptions

            self.logger.error("Unexpected error:", sys.exc_info()[0])