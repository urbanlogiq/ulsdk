import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Task, TaskT } from './task';
export declare class TaskList implements flatbuffers.IUnpackableObject<TaskListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): TaskList;
    static getRootAsTaskList(bb: flatbuffers.ByteBuffer, obj?: TaskList): TaskList;
    static getSizePrefixedRootAsTaskList(bb: flatbuffers.ByteBuffer, obj?: TaskList): TaskList;
    tasks(index: number, obj?: Task): Task | null;
    tasksLength(): number;
    static startTaskList(builder: flatbuffers.Builder): void;
    static addTasks(builder: flatbuffers.Builder, tasksOffset: flatbuffers.Offset): void;
    static createTasksVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startTasksVector(builder: flatbuffers.Builder, numElems: number): void;
    static endTaskList(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createTaskList(builder: flatbuffers.Builder, tasksOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): TaskListT;
    unpackTo(_o: TaskListT): void;
}
export declare class TaskListT implements flatbuffers.IGeneratedObject {
    tasks: (TaskT)[];
    constructor(tasks?: (TaskT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=task-list.d.ts.map