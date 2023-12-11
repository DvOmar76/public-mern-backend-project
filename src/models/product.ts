import mongoose, { Document } from 'mongoose';
export type ProductDocument = Document & {
  name: string;
  products: { product: string; quantity: number }[];
  description: string;
  quantity: number;
  price: number;
  image: string[];
  variants: string[];
  sizes: string[];
  categories: string[];
};

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    index: true,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  quantity: {
    type: Number,
    default: 1,
  },
  price: {
    type: Number,
    required: true,
  },
  variants: {
    type: [String],
  },
  sizes: {
    type: [String],
  },
  image: {
    type: [String],
  },
  categories: {
    type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Category' }],
    required: true,
  },
});

export default mongoose.model<ProductDocument>('Product', productSchema);
