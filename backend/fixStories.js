const mongoose = require('mongoose');
const Story = require('./models/Story'); // adjust path if different

const uri = 'mongodb://localhost:27017/yourDatabaseName';

(async () => {
  try {
    await mongoose.connect(uri);
    const result = await Story.updateMany(
      { viewers: { $exists: false } },
      { $set: { viewers: [] } }
    );
    console.log(`Updated ${result.modifiedCount} stories`);
  } catch (err) {
    console.error(err);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
})();
