import type IReadingTime from "./IReadingTime";

export default interface IMetadata {
	title: string;
	date: string;
    author: string;
	readingTime : IReadingTime;
	tags : string;
	description : string;
};

