/**
 * @name ghostscript-67d760ab775dae4efe803b5944b0439aa3c0b04a-seticc
 * @id cpp/ghostscript/67d760ab775dae4efe803b5944b0439aa3c0b04a/seticc
 * @description ghostscript-67d760ab775dae4efe803b5944b0439aa3c0b04a-psi/zicc.c-seticc CVE-2018-19476
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpnameval_53, BlockStmt target_2, AddressOfExpr target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpnameval_53
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vICCdict_45, Variable vpnameval_53, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(FunctionCall).getTarget().hasName("dict_find_string")
		and target_1.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vICCdict_45
		and target_1.getGreaterOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Name"
		and target_1.getGreaterOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpnameval_53
		and target_1.getLesserOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vpnameval_53, BlockStmt target_2) {
		target_2.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="bytes"
		and target_2.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_2.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpnameval_53
		and target_2.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint")
}

predicate func_3(Variable vpnameval_53, AddressOfExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vpnameval_53
}

from Function func, Parameter vICCdict_45, Variable vpnameval_53, RelationalOperation target_1, BlockStmt target_2, AddressOfExpr target_3
where
not func_0(vpnameval_53, target_2, target_3)
and func_1(vICCdict_45, vpnameval_53, target_2, target_1)
and func_2(vpnameval_53, target_2)
and func_3(vpnameval_53, target_3)
and vICCdict_45.getType().hasName("ref *")
and vpnameval_53.getType().hasName("ref *")
and vICCdict_45.getFunction() = func
and vpnameval_53.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
