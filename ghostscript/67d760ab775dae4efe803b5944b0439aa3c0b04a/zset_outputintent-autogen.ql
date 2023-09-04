/**
 * @name ghostscript-67d760ab775dae4efe803b5944b0439aa3c0b04a-zset_outputintent
 * @id cpp/ghostscript/67d760ab775dae4efe803b5944b0439aa3c0b04a/zset-outputintent
 * @description ghostscript-67d760ab775dae4efe803b5944b0439aa3c0b04a-psi/zicc.c-zset_outputintent CVE-2018-19476
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpnval_232, AddressOfExpr target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpnval_232
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_0)
		and target_1.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpnval_232, AddressOfExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vpnval_232
}

predicate func_2(Variable vpnval_232, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="intval"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpnval_232
}

from Function func, Variable vpnval_232, AddressOfExpr target_1, ExprStmt target_2
where
not func_0(vpnval_232, target_1, target_2, func)
and func_1(vpnval_232, target_1)
and func_2(vpnval_232, target_2)
and vpnval_232.getType().hasName("ref *")
and vpnval_232.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()