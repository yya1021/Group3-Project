const config = require('./config');
const { createApp } = require('./app');

const app = createApp();

app.listen(config.PORT);
