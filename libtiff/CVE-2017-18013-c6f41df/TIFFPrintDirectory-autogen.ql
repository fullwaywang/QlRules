/**
 * @name libtiff-c6f41df7b581402dfba3c19a1e3df4454c551a01-TIFFPrintDirectory
 * @id cpp/libtiff/c6f41df7b581402dfba3c19a1e3df4454c551a01/TIFFPrintDirectory
 * @description libtiff-c6f41df7b581402dfba3c19a1e3df4454c551a01-libtiff/tif_print.c-TIFFPrintDirectory CVE-2017-18013
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtd_236, Variable vs_659, RelationalOperation target_4) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="td_stripoffset"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_236
		and target_0.getThen() instanceof ArrayExpr
		and target_0.getElse().(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="    %3lu: [%8llu, %8llu]\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_659
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof ArrayExpr
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtd_236, Variable vs_659, ArrayExpr target_2) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition().(PointerFieldAccess).getTarget().getName()="td_stripbytecount"
		and target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_236
		and target_1.getThen() instanceof ArrayExpr
		and target_1.getElse().(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="    %3lu: [%8llu, %8llu]\n"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_659
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof ArrayExpr
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vtd_236, Variable vs_659, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="td_stripoffset"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_236
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vs_659
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="    %3lu: [%8llu, %8llu]\n"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_659
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="td_stripbytecount"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_236
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vs_659
}

/*predicate func_3(Variable vtd_236, Variable vs_659, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="td_stripbytecount"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_236
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vs_659
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="    %3lu: [%8llu, %8llu]\n"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_659
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="td_stripoffset"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_236
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vs_659
}

*/
predicate func_4(Variable vtd_236, Variable vs_659, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vs_659
		and target_4.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="td_nstrips"
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_236
}

from Function func, Variable vtd_236, Variable vs_659, ArrayExpr target_2, RelationalOperation target_4
where
not func_0(vtd_236, vs_659, target_4)
and not func_1(vtd_236, vs_659, target_2)
and func_2(vtd_236, vs_659, target_2)
and func_4(vtd_236, vs_659, target_4)
and vtd_236.getType().hasName("TIFFDirectory *")
and vs_659.getType().hasName("uint32")
and vtd_236.(LocalVariable).getFunction() = func
and vs_659.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
