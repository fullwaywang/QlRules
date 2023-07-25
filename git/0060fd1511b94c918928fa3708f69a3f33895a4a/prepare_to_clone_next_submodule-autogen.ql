/**
 * @name git-0060fd1511b94c918928fa3708f69a3f33895a4a-prepare_to_clone_next_submodule
 * @id cpp/git/0060fd1511b94c918928fa3708f69a3f33895a4a/prepare-to-clone-next-submodule
 * @description git-0060fd1511b94c918928fa3708f69a3f33895a4a-builtin/submodule--helper.c-prepare_to_clone_next_submodule CVE-2019-1349
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vchild_779, Parameter vsuc_780, AddressOfExpr target_1, AddressOfExpr target_2, LogicalAndExpr target_3, ValueFieldAccess target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="require_init"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsuc_780
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("argv_array_push")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="args"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchild_779
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="--require-init"
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_0)
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vchild_779, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="args"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchild_779
}

predicate func_2(Parameter vchild_779, AddressOfExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="args"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchild_779
}

predicate func_3(Parameter vsuc_780, LogicalAndExpr target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="recommend_shallow"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsuc_780
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="recommend_shallow"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_4(Parameter vsuc_780, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="nr"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="references"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsuc_780
}

from Function func, Parameter vchild_779, Parameter vsuc_780, AddressOfExpr target_1, AddressOfExpr target_2, LogicalAndExpr target_3, ValueFieldAccess target_4
where
not func_0(vchild_779, vsuc_780, target_1, target_2, target_3, target_4, func)
and func_1(vchild_779, target_1)
and func_2(vchild_779, target_2)
and func_3(vsuc_780, target_3)
and func_4(vsuc_780, target_4)
and vchild_779.getType().hasName("child_process *")
and vsuc_780.getType().hasName("submodule_update_clone *")
and vchild_779.getParentScope+() = func
and vsuc_780.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
