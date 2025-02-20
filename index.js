const Express = require("express");
const MongoClient = require("mongodb").MongoClient;
const cors = require("cors");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const path = require('path');


const app = Express();
app.use(cors());
app.use(Express.json());


const CONNECTION_STRING = "mongodb+srv://leaflens:leaflens@cluster0.gpg4e.mongodb.net/LeafLens?retryWrites=true&w=majority&tlsAllowInvalidCertificates=true";
const DATABASENAME = "LeafLens";
const SECRET_KEY = 'your_secret_key'; 

const { ObjectId } = require('mongodb');


let database;

app.listen(5038, () => {
    MongoClient.connect(CONNECTION_STRING, { useNewUrlParser: true, useUnifiedTopology: true }, (error, client) => {
        if (error) {
            console.error("Connection failed", error);
            return;
        }
        database = client.db(DATABASENAME);
        console.log("Connected to database successfully");
    });
});

// Registration endpoint
app.post("/register", async (req, res) => {
    const { username, contact_number, password, under_by } = req.body; 
    const defaultProfileImagePath = './assets/default-profile.png'; 

    try {
        // Check if the username already exists
        const existingUserByUsername = await database.collection("users").findOne({ username });
        if (existingUserByUsername) {
            return res.status(400).json({ message: "Username already exists, please use another username." });
        }

        // Check if the contact number already exists
        const existingUserByContact = await database.collection("users").findOne({ contact_number });
        if (existingUserByContact) {
            return res.status(400).json({ message: "Contact number already exists, please use another number." });
        }

        // Hash the user's password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user with unique username and contact number
        const newUser = await database.collection("users").insertOne({
            username,
            contact_number,
            password: hashedPassword,
            profileImagePath: defaultProfileImagePath,
            status: 'pending',
            user_type: 'farmer', 
            under_by, 
        });

        res.status(201).json({ message: "User registered successfully but still on confirmation, please wait for the approval of the admin" });
    } catch (error) {
        console.error("Error registering user:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await database.collection("users").findOne({ username: username });

        if (!user) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        if (user.status === "pending") {
            return res.status(403).json({ message: "Your account is awaiting admin approval." });
        }

        const token = jwt.sign({ 
            userId: user._id, 
            username: user.username,  // Ensure username is included
            user_type: user.user_type 
        }, SECRET_KEY);

        await database.collection("users").updateOne(
            { _id: user._id },
            { $set: { lastLogin: new Date() } }
        );

        return res.status(200).json({ 
            token, 
            status: user.status,
            userId: user._id,  
            user_type: user.user_type // Include user_type in the response
        });

    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


// Middleware to verify token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: "Access denied, token missing!" });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: "Invalid token" });
        }
        req.user = user;
        next();
    });

};

// Logout endpoint
app.post("/logout", authenticateToken, async (req, res) => {
    try {
        // Invalidate the token (optional, depending on your token strategy)
        // You can blacklist the token here if necessary

        res.status(200).json({ message: "Logout successful" });
    } catch (error) {
        console.error("Error during logout:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Endpoint to get the username of the logged-in user
app.get("/get-username", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;  // Get userId from the token
        const user = await database.collection("users").findOne({ _id: ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Return the username of the user
        return res.status(200).json({ username: user.username });
    } catch (error) {
        console.error("Error fetching username:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


// Fetch user details

app.get('/get-user-details', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // Convert userId to ObjectId
        const userObjectId = ObjectId(userId); 

        // Fetch user data from 'users' collection
        const user = await database.collection('users').findOne({ _id: userObjectId });

        // Fetch user profile data from 'user_profile' collection using 'userId'
        const profile = await database.collection('user_profile').findOne({ userId: userId });

        if (user && profile) {
            res.json({
                username: user.username,
                contact_number: user.contact_number,
                email: profile.email,
                zone_no: profile.zone_no,
                gender: profile.gender,
                age: profile.age,
            });
        } else {
            res.status(404).json({ message: 'User profile not found' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post("/save-rice-data", authenticateToken, async (req, res) => {
    const { variety, plantingDate, SQM } = req.body;
  
    // Validate if the date is valid
    if (!plantingDate || isNaN(Date.parse(plantingDate))) {
      return res.status(400).json({ message: "Invalid planting date" });
    }
  
    try {
      const result = await database.collection("farm_details").insertOne({
        userId: req.user.userId,
        variety: variety,
        dateOfPlanting: new Date(plantingDate), // Convert to Date object
        SQM: SQM,
        timestamp: new Date(),
      });
  
      res.status(201).json({ message: "Rice data saved successfully" });
    } catch (error) {
      console.error("Error saving rice data:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  
// Update farm details endpoint (Protected)
app.post("/update-farm-details", authenticateToken, async (req, res) => {
    try {
        const { farmName, location, plantingDate, SQM, variety } = req.body;

        const updateData = {
            farmName,
            location,
            plantingDate,
            SQM,
            variety,
            timestamp: new Date()
        };

        await database.collection("user_farm_details").updateOne(
            { userId: req.user.userId },
            { $set: updateData },
            { upsert: true } 
        );

        res.json({ message: "Farm details updated successfully" });
    } catch (error) {
        console.error("Error updating farm details:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Fetch rice varieties endpoint (Protected)
app.get("/get-rice-varieties", authenticateToken, async (req, res) => {
    try {
        const riceVarieties = await database.collection("rice_variety").find({}).toArray();
        const varieties = riceVarieties.map(item => item.variety);
        res.json(varieties);
    } catch (error) {
        console.error("Error fetching rice varieties:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Update profile image path endpoint (Protected)
app.post("/update-profile-image", authenticateToken, async (req, res) => {
    const { imagePath } = req.body;

    try {
        if (!imagePath) {
            return res.status(400).json({ message: "Image path is required" });
        }

        await database.collection("user_profile").updateOne(
            { userId: req.user.userId },
            { $set: { profileImagePath: imagePath } },
            { upsert: true } 
        );

        res.status(200).json({ message: "Profile image updated successfully" });
    } catch (error) {
        console.error("Error updating profile image:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Get profile image path endpoint (Protected)
app.get("/get-profile-image", authenticateToken, async (req, res) => {
    try {
        const userProfile = await database.collection("user_profile").findOne({ userId: req.user.userId });

        if (!userProfile || !userProfile.profileImagePath) {
            return res.json({ imagePath: './assets/profile.png' });
        }

        res.json({ imagePath: userProfile.profileImagePath });
    } catch (error) {
        console.error("Error fetching profile image:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.post("/update-user-profile", authenticateToken, async (req, res) => {
    const { imagePath, email, zoneNo, gender, age } = req.body;

    try {
        // Create an update object dynamically based on provided fields
        const updateFields = {};
        if (imagePath) updateFields.profileImagePath = imagePath;
        if (email) updateFields.email = email;
        if (zoneNo) updateFields.zone_no = zoneNo;
        if (gender) updateFields.gender = gender;
        if (age) updateFields.age = age;

        // Check if there's anything to update
        if (Object.keys(updateFields).length === 0) {
            return res.status(400).json({ message: "At least one field is required" });
        }

        await database.collection("user_profile").updateOne(
            { userId: req.user.userId },
            { $set: updateFields },
            { upsert: true }
        );

        res.status(200).json({ message: "Profile updated successfully" });
    } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
});


// Get user-specific farm data from both collections (Protected)
app.get("/user-farm-data", authenticateToken, async (req, res) => {
    try {
        const farmDetails = await database.collection("farm_details").findOne(
            { userId: req.user.userId },
            { sort: { timestamp: -1 } }
        );

        const userFarmDetails = await database.collection("user_farm_details").findOne(
            { userId: req.user.userId },
            { sort: { timestamp: -1 } }
        );

        const response = {
            SQM: farmDetails?.SQM || '',
            variety: farmDetails?.variety || '',
            farmName: userFarmDetails?.farmName || '',
            location: userFarmDetails?.location || '',
            plantingDate: userFarmDetails?.plantingDate || '',
        };

        res.json(response);
    } catch (error) {
        console.error("Error fetching user farm data:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Add new rice variety endpoint (Protected)
app.post("/add-rice-variety", authenticateToken, async (req, res) => {
    const { variety, age } = req.body;

    try {
        // Check if the rice variety already exists
        const existingVariety = await database.collection("rice_variety").findOne({ variety: variety });
        if (existingVariety) {
            return res.status(400).json({ message: "Rice variety already exists" });
        }

        // Insert the new variety
        await database.collection("rice_variety").insertOne({
            variety: variety,
            age: parseInt(age, 10)
        });

        res.status(201).json({ message: "Rice variety added successfully" });
    } catch (error) {
        console.error("Error adding rice variety:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Remove rice variety endpoint (Protected)
app.delete("/remove-rice-variety", authenticateToken, async (req, res) => {
    const { variety } = req.body;

    try {
        // Remove the rice variety
        const result = await database.collection("rice_variety").deleteOne({ variety: variety });

        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Rice variety not found" });
        }

        res.status(200).json({ message: "Rice variety removed successfully" });
    } catch (error) {
        console.error("Error removing rice variety:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

//Endpoint for fetching user accounts
app.get("/get-usernames", authenticateToken, async (req, res) => {
    try {
        const { userId } = req.user;
        
        // Fetch the logged-in admin's data
        const loggedInAdmin = await database.collection("users").findOne({ _id: new ObjectId(userId) });

        if (!loggedInAdmin) {
            return res.status(404).json({ message: "User not found" });
        }

        let users;
        if (loggedInAdmin.user_type === "main admin") {
            // Main admin sees all users except himself
            users = await database.collection("users").find({ username: { $ne: loggedInAdmin.username } }).toArray();
        } else {
            // Regular admin sees only farmers under them, excluding themselves
            users = await database.collection("users").find({
                under_by: loggedInAdmin.username,
                username: { $ne: loggedInAdmin.username }  // Exclude logged-in admin
            }).toArray();
        }

        res.status(200).json(users);
    } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});




// Delete user by username (Protected)
app.delete("/delete-user", authenticateToken, async (req, res) => {
    const { username } = req.body;

    try {
        // Prevent deletion of admin account
        if (username === 'LeafLens Admin') {
            return res.status(400).json({ message: "Cannot delete admin account" });
        }

        const result = await database.collection("users").deleteOne({ username: username });

        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({ message: "User deleted successfully" });
    } catch (error) {
        console.error("Error deleting user:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


// Save image path endpoint (Protected)
app.post("/save-image-path", authenticateToken, async (req, res) => {
    const { imagePath } = req.body;

    try {
        if (!imagePath) {
            return res.status(400).json({ message: "Image path is required" });
        }

        // Here you might want to save this image path to a user's specific collection or document
        await database.collection("user_rice_images").insertOne({
            userId: req.user.userId,
            imagePath: imagePath,
            timestamp: new Date()
        });

        res.status(200).json({ message: "Image path saved successfully" });
    } catch (error) {
        console.error("Error saving image path:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


// Fetch History
app.get("/history", authenticateToken, async (req, res) => {
    try {
        // Fetch all past results for the user from the "result" collection
        const userResults = await database.collection("result").find({ userId: req.user.userId }).sort({ timestamp: -1 }).toArray();

        res.json(userResults);
    } catch (error) {
        console.error("Error fetching history:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


// Approve user
app.post("/admin/approve-account", async (req, res) => {
    const { userId } = req.body;

    try {
        const result = await database.collection("users").updateOne(
            { _id: new ObjectId(userId) },
            { $set: { status: "approved" } }
        );

        if (result.modifiedCount === 1) {
            res.status(200).json({ message: "User approved successfully" });
        } else {
            res.status(404).json({ message: "User not found" });
        }
    } catch (error) {
        console.error("Error approving user:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Reject and delete user
app.post("/admin/reject-account", async (req, res) => {
    const { userId } = req.body;

    try {
        const result = await database.collection("users").deleteOne({ _id: new ObjectId(userId) });

        if (result.deletedCount === 1) {
            res.status(200).json({ message: "User rejected and deleted successfully" });
        } else {
            res.status(404).json({ message: "User not found" });
        }
    } catch (error) {
        console.error("Error rejecting user:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.post('/change-password', async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const token = req.headers['authorization'].split(' ')[1];

    try {
    
        const decoded = jwt.verify(token, SECRET_KEY);
        const userId = decoded.userId;  

        if (!database) {
            return res.status(500).json({ message: 'Database connection not established' });
        }

        // Fetch the user from the database using 'userId'
        const user = await database.collection('users').findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Compare old password
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Incorrect old password' });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the password in the database
        await database.collection('users').updateOne(
            { _id: new ObjectId(userId) },
            { $set: { password: hashedPassword } }
        );

        res.status(200).json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Password Reset Endpoint
app.post('/reset-password', async (req, res) => {
    const { username, newPassword } = req.body;

    try {
        // Find the user by username in the users collection
        const user = await database.collection("users").findOne({ username });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Hash the new password using bcrypt
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the user's password in the database
        await database.collection("users").updateOne(
            { username },
            { $set: { password: hashedPassword } } // Ensure to store the hashed password
        );

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});


app.get("/estimate-harvest", authenticateToken, async (req, res) => {
    try {
        const farmDetails = await database.collection("farm_details").findOne(
            { userId: req.user.userId },
            { sort: { timestamp: -1 } }
        );

        if (!farmDetails) {
            return res.status(404).json({ message: "No farm details found for this user" });
        }

        const { variety, dateOfPlanting, SQM } = farmDetails;
        const varietyDetails = await database.collection("rice_variety").findOne({ variety });

        if (!varietyDetails) {
            return res.status(404).json({ message: "No such variety found" });
        }

        const varietyAge = varietyDetails.age; // Expected lifespan of the crop
        const plantingDate = new Date(dateOfPlanting);
        const today = new Date();
        const elapsedDays = Math.floor((today - plantingDate) / (1000 * 60 * 60 * 24));
        const remainingDays = varietyAge - elapsedDays;

        if (remainingDays < 0) {
            return res.status(400).json({ message: "Rice is past its estimated harvest date" });
        }

        const estimatedHarvestDate = new Date(plantingDate);
        estimatedHarvestDate.setDate(plantingDate.getDate() + varietyAge);

        // Fetch predictions for fertilizer suggestion
        const predictions = await database.collection("model_prediction")
            .find({ userId: req.user.userId })
            .sort({ createdAt: -1 })
            .limit(10)
            .toArray();

        let fertilizerSuggestion = 'Your rice crop is healthy! No fertilizer needed.';
        const counts = { 0: 0, 1: 0, 2: 0, 3: 0 };

        // Count predictions based on case results
        predictions.forEach(prediction => {
            const result = prediction.second_model_class;
            counts[result] = (counts[result] || 0) + 1;
        });

        const total0and1 = counts[0] + counts[1];
        const total2and3 = counts[2] + counts[3];

        if (total0and1 >= 6) {
            const urea = 0.0075 * parseFloat(SQM); // Calculate urea in kilograms
            const ammoniumSulfate = 0.0175 * parseFloat(SQM); // Calculate ammonium sulfate in kilograms
            fertilizerSuggestion = `Apply ${urea.toFixed(2)} kg of urea (46-0-0) or ${ammoniumSulfate.toFixed(2)} kg of ammonium sulfate (21-0-0) in your ${SQM} sqm.`;
        } else if (total2and3 >= 6) {
            fertilizerSuggestion = 'Your rice crop is healthy! No fertilizer needed.';
        }

        // Save the result into the 'result' collection
        const result = {
            userId: req.user.userId,
            variety,
            dateOfPlanting,
            SQM,
            estimatedHarvest: `You have ${remainingDays} days until harvest`,
            harvestDate: estimatedHarvestDate.toDateString(),
            fertilizerSuggestions: fertilizerSuggestion,
            timestamp: new Date()
        };

        await database.collection("result").insertOne(result);
        res.json(result);
    } catch (error) {
        console.error("Error estimating harvest:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});



app.get('/fertilizer-schedule', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; // Assuming user ID is added to the token payload
        const userFarmDetailsCollection = database.collection('user_farm_details');

        const userFarmDetails = await userFarmDetailsCollection.findOne({ userId });

        if (!userFarmDetails) {
            return res.status(404).json({ message: 'User farm details not found' });
        }

        // Fetch and parse planting date
        const plantingDate = new Date(userFarmDetails.plantingDate);

        // Check if planting date is valid
        if (isNaN(plantingDate.getTime())) {
            console.error("Invalid planting date format:", userFarmDetails.plantingDate);
            return res.status(400).json({ message: 'Invalid planting date format' });
        }

        // Calculate fertilizer schedule
        const fertilizerSchedule = {
            day15: new Date(plantingDate),
            day30: new Date(plantingDate),
        };

        // Set dates for 15 and 30 days after planting date
        fertilizerSchedule.day15.setDate(plantingDate.getDate() + 15);
        fertilizerSchedule.day30.setDate(plantingDate.getDate() + 30);

        // Convert dates to ISO format for consistent transmission
        res.status(200).json({
            day15: fertilizerSchedule.day15.toISOString(),
            day30: fertilizerSchedule.day30.toISOString(),
        });
    } catch (error) {
        console.error('Error retrieving planting date:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/get-fertilizer-suggestion', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; // Assuming user ID is added to the token payload
        const resultCollection = database.collection('result');

        // Find the user's result based on the userId
        const userResult = await resultCollection.findOne({ userId });

        if (!userResult) {
            return res.status(404).json({ message: 'User result not found' });
        }

        // Assuming the fertilizer suggestion is stored under the field 'fertilizerSuggestion'
        const fertilizerSuggestion = userResult.fertilizerSuggestions;

        if (!fertilizerSuggestion) {
            return res.status(404).json({ message: 'Fertilizer suggestion not found for the user' });
        }

        // Respond with the fertilizer suggestion
        res.status(200).json({
            suggestion: fertilizerSuggestion,
        });
    } catch (error) {
        console.error('Error retrieving fertilizer suggestion:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/get-logged-in-user', authenticateToken, async (req, res) => {
    try {
        const userId = new ObjectId(req.user.userId); // Extract user ID from token

        const user = await database.collection("users").findOne(
            { _id: userId },
            { projection: { username: 1, user_type: 1, contact_number: 1 } } // Only return needed fields
        );

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({ username: user.username, user_type: user.user_type, contact_number: user.contact_number });
    } catch (error) {
        console.error("Error fetching logged-in user:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


//fetching cooperative
app.get('/get-admin-users', async (req, res) => {
    try {
        const admins = await database.collection("users")
            .find({ user_type: 'admin' })
            .project({ username: 1, _id: 0 }) // Use `.project()` instead of `.select()`
            .toArray();

        res.status(200).json({ success: true, adminUsers: admins });
    } catch (error) {
        console.error('Error fetching admin users:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

//  Fetch All Users (Farmers & Admins)
app.get('/get-users', async (req, res) => {
    try {
        const users = await database.collection("users")
            .find({ user_type: { $in: ["farmer", "admin"] } })
            .toArray();

        res.json(users);
    } catch (error) {
        res.status(500).json({ message: "Error fetching users", error });
    }
});

//  Promote or Demote User
app.post('/update-user', async (req, res) => {
    const { userId, user_type } = req.body;

    if (!userId || !["farmer", "admin"].includes(user_type)) {
        return res.status(400).json({ message: "Invalid request data" });
    }

    try {
        const updatedUser = await database.collection("users").findOneAndUpdate(
            { _id: new ObjectId(userId) }, 
            { $set: { user_type } },
            { returnDocument: "after" }
        );

        if (!updatedUser.value) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: `User is now a ${user_type}`, user: updatedUser.value });
    } catch (error) {
        res.status(500).json({ message: "Error updating user", error });
    }
});

app.get("/admin/pending-accounts", authenticateToken, async (req, res) => {
    try {
        const admin = await database.collection("users").findOne({ username: req.user.username });

        if (!admin) {
            return res.status(404).json({ message: "Admin not found" });
        }

        let query = { status: "pending" };

        if (admin.user_type === "main admin") {

        } else {
            query.under_by = admin.username;

        }

        const pendingUsers = await database.collection("users").find(query).toArray();

        res.json(pendingUsers);
    } catch (error) {
        console.error("Error fetching pending accounts:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


// Catch-all route to handle undefined routes
app.use((req, res) => {
    res.status(404).json({ message: "Route not found" });
});
