/**
 * @name linux-030e2c78d3a91dd0d27fef37e91950dde333eba1-snd_seq_ioctl_remove_events
 * @id cpp/linux/030e2c78d3a91dd0d27fef37e91950dde333eba1/snd_seq_ioctl_remove_events
 * @description linux-030e2c78d3a91dd0d27fef37e91950dde333eba1-snd_seq_ioctl_remove_events 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vclient_1949) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(ValueFieldAccess).getTarget().getName()="fifo"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="user"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclient_1949
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snd_seq_fifo_clear")
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="fifo"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="user"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclient_1949)
}

predicate func_1(Parameter vclient_1949) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclient_1949
		and target_1.getAnOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snd_seq_fifo_clear")
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="fifo"
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="user"
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclient_1949)
}

from Function func, Parameter vclient_1949
where
not func_0(vclient_1949)
and func_1(vclient_1949)
and vclient_1949.getType().hasName("snd_seq_client *")
and vclient_1949.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
