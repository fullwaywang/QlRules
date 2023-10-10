/**
 * @name linux-f05819df10d7b09f6d1eb6f8534a8f68e5a4fe61-key_gc_unused_keys
 * @id cpp/linux/f05819df10d7b09f6d1eb6f8534a8f68e5a4fe61/key-gc-unused-keys
 * @description linux-f05819df10d7b09f6d1eb6f8534a8f68e5a4fe61-key_gc_unused_keys 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vkey_130) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("constant_test_bit")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_130
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("variable_test_bit")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_130
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("constant_test_bit")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(Literal).getValue()="5"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_130
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("variable_test_bit")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(Literal).getValue()="5"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_130
		and target_0.getAnOperand() instanceof PointerFieldAccess
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="destroy"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="type"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_130
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vkey_130)
}

predicate func_1(Variable vkey_130) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="destroy"
		and target_1.getQualifier().(ValueFieldAccess).getTarget().getName()="type"
		and target_1.getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_1.getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_1.getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_130)
}

predicate func_2(Variable vkey_130) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="serial"
		and target_2.getQualifier().(VariableAccess).getTarget()=vkey_130)
}

from Function func, Variable vkey_130
where
not func_0(vkey_130)
and func_1(vkey_130)
and vkey_130.getType().hasName("key *")
and func_2(vkey_130)
and vkey_130.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
