/**
 * @name redis-6cbea7d29b5285692843bc1c351abba1a7ef326f-processCommand
 * @id cpp/redis/6cbea7d29b5285692843bc1c351abba1a7ef326f/processCommand
 * @description redis-6cbea7d29b5285692843bc1c351abba1a7ef326f-src/server.c-processCommand CVE-2021-31294
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_3946, Variable vis_write_command_3988, Variable vis_may_replicate_command_3996, ExprStmt target_1, LogicalAndExpr target_2, LogicalAndExpr target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3946
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="1"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vis_may_replicate_command_3996
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vis_write_command_3988
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("rejectCommandFormat")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_3946
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Replica can't interract with the keyspace"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vc_3946, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("rejectCommand")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_3946
		and target_1.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="slowscripterr"
		and target_1.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("sharedObjectsStruct")
}

predicate func_2(Parameter vc_3946, Variable vis_may_replicate_command_3996, LogicalAndExpr target_2) {
		target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3946
		and target_2.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="1"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="client_pause_type"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("redisServer")
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="client_pause_type"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("redisServer")
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_may_replicate_command_3996
}

predicate func_3(Parameter vc_3946, Variable vis_write_command_3988, LogicalAndExpr target_3) {
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="masterhost"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("redisServer")
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="repl_slave_ro"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("redisServer")
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3946
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="2"
		and target_3.getAnOperand().(VariableAccess).getTarget()=vis_write_command_3988
}

from Function func, Parameter vc_3946, Variable vis_write_command_3988, Variable vis_may_replicate_command_3996, ExprStmt target_1, LogicalAndExpr target_2, LogicalAndExpr target_3
where
not func_0(vc_3946, vis_write_command_3988, vis_may_replicate_command_3996, target_1, target_2, target_3, func)
and func_1(vc_3946, target_1)
and func_2(vc_3946, vis_may_replicate_command_3996, target_2)
and func_3(vc_3946, vis_write_command_3988, target_3)
and vc_3946.getType().hasName("client *")
and vis_write_command_3988.getType().hasName("int")
and vis_may_replicate_command_3996.getType().hasName("int")
and vc_3946.getFunction() = func
and vis_write_command_3988.(LocalVariable).getFunction() = func
and vis_may_replicate_command_3996.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
