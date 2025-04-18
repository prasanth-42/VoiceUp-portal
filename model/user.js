const mongoose=require('mongoose');

const userschema=  mongoose.Schema({
      username:String,
      name:String,
      age:Number,
      email:String,
      password:String,
      role: {
        type: String,
        enum: ['ADMIN', 'CITIZEN', 'OFFICER'],
        default: 'CITIZEN'
      },
      // Officer-specific fields
      department: {
        type: String,
        required: function() {
          return this.role === 'OFFICER';
        },
        enum: ['INFRASTRUCTURE', 'WATER_SUPPLY', 'ELECTRICITY', 'SANITATION', 'HEALTHCARE', 'EDUCATION', 'TRANSPORTATION', 'OTHER']
      },
      city: {
        type: String,
        required: function() {
          return this.role === 'OFFICER';
        }
      },
      state: {
        type: String,
        required: function() {
          return this.role === 'OFFICER';
        }
      },
      posts:[{type:mongoose.Schema.Types.ObjectId,ref:"post"}],
      comments:[{type:mongoose.Schema.Types.ObjectId,ref:"comment"}]
})

module.exports=mongoose.model("user",userschema);