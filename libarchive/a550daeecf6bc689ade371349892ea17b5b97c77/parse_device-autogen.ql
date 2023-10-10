/**
 * @name libarchive-a550daeecf6bc689ade371349892ea17b5b97c77-parse_device
 * @id cpp/libarchive/a550daeecf6bc689ade371349892ea17b5b97c77/parse-device
 * @description libarchive-a550daeecf6bc689ade371349892ea17b5b97c77-libarchive/archive_read_support_format_mtree.c-parse_device CVE-2016-4301
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vargc_1364, BlockStmt target_4, ExprStmt target_5, RelationalOperation target_6) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vargc_1364
		and target_0.getLesserOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vargc_1364, BlockStmt target_4, VariableAccess target_1) {
		target_1.getTarget()=vargc_1364
		and target_1.getParent().(GTExpr).getLesserOperand().(Literal).getValue()="3"
		and target_1.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vargc_1364, BlockStmt target_4, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vargc_1364
		and target_3.getLesserOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="84"
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Too many arguments"
		and target_4.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-20"
}

predicate func_5(Variable vargc_1364, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vargc_1364
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mtree_atol")
}

predicate func_6(Variable vargc_1364, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vargc_1364
		and target_6.getGreaterOperand().(Literal).getValue()="2"
}

from Function func, Variable vargc_1364, VariableAccess target_1, RelationalOperation target_3, BlockStmt target_4, ExprStmt target_5, RelationalOperation target_6
where
not func_0(vargc_1364, target_4, target_5, target_6)
and func_1(vargc_1364, target_4, target_1)
and func_3(vargc_1364, target_4, target_3)
and func_4(target_4)
and func_5(vargc_1364, target_5)
and func_6(vargc_1364, target_6)
and vargc_1364.getType().hasName("int")
and vargc_1364.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
