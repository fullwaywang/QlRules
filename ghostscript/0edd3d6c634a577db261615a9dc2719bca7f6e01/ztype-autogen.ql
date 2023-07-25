/**
 * @name ghostscript-0edd3d6c634a577db261615a9dc2719bca7f6e01-ztype
 * @id cpp/ghostscript/0edd3d6c634a577db261615a9dc2719bca7f6e01/ztype
 * @description ghostscript-0edd3d6c634a577db261615a9dc2719bca7f6e01-psi/ztype.c-ztype CVE-2018-16511
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_2, Function func) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vop_69, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(ValueFieldAccess).getTarget().getName()="pstruct"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vop_69
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-1"
		and target_1.getAnOperand().(HexLiteral).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vop_69, EqualityOperation target_1, BlockStmt target_2
where
not func_0(target_2, func)
and func_1(vop_69, target_2, target_1)
and func_2(target_2)
and vop_69.getType().hasName("os_ptr")
and vop_69.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
