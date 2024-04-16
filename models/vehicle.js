const mongoose = require('mongoose');

const vehicleSchema = new mongoose.Schema({
    ownerName: { type: String, required: true },
    ownerContact: { type: String, required: true },
    ownerEmail: { type: String, required: true },
    ownerCity: { type: String, required: true },
    vehicleType: { type: String, required: true },
    brand: { type: String, required: true },
    model: { type: String, required: true },
    variant: { type: String, required: true },
    location: { type: String, required: true },
    rtoCode: { type: String },
    batteryPower: { type: String, required: true },
    kilometresDriven: { type: String },
    bodyType: { type: String },
    color: { type: String, required: true },
    registrationYear: { type: String, required: true },
    vehicleDescription: { type: String, required: true },
    transmissionType: { type: String },
    interiorImages: [{ type: String, required: true }],
    frontImages: [{ type: String, required: true }],
    sideImages: [{ type: String, required: true }],
    backImages: [{ type: String, required: true }],
    price: {
        currency: { type: String, required: true },
        value: { type: Number, required: true }
    }
});

const Vehicle = mongoose.model('Vehicle', vehicleSchema);

module.exports = Vehicle;
