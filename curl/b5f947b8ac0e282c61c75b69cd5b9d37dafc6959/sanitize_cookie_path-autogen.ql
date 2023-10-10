/**
 * @name curl-b5f947b8ac0e282c61c75b69cd5b9d37dafc6959-sanitize_cookie_path
 * @id cpp/curl/b5f947b8ac0e282c61c75b69cd5b9d37dafc6959/sanitize-cookie-path
 * @description curl-b5f947b8ac0e282c61c75b69cd5b9d37dafc6959-lib/cookie.c-sanitize_cookie_path CVE-2015-3145
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_222) {
	exists(PostfixDecrExpr target_0 |
		target_0.getOperand().(VariableAccess).getTarget()=vlen_222)
}

predicate func_3(Variable vlen_222, Variable vnew_path_223, EqualityOperation target_13) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnew_path_223
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_222
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13)
}

predicate func_5(Variable vlen_222, EqualityOperation target_13) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vlen_222
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13)
}

predicate func_6(Variable vlen_222, BlockStmt target_14, ExprStmt target_15) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand().(VariableAccess).getTarget()=vlen_222
		and target_6.getAnOperand() instanceof EqualityOperation
		and target_6.getParent().(IfStmt).getThen()=target_14
		and target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_7(Variable vlen_222, Variable vnew_path_223, BlockStmt target_14, EqualityOperation target_7) {
		target_7.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnew_path_223
		and target_7.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_222
		and target_7.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getAnOperand().(CharLiteral).getValue()="47"
		and target_7.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_14
}

predicate func_8(Variable vlen_222, VariableAccess target_8) {
		target_8.getTarget()=vlen_222
}

predicate func_9(Variable vnew_path_223, EqualityOperation target_13, FunctionCall target_9) {
		target_9.getTarget().hasName("strlen")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vnew_path_223
		and target_9.getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_10(Variable vnew_path_223, ExprStmt target_16, FunctionCall target_10) {
		target_10.getTarget().hasName("strlen")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vnew_path_223
		and target_10.getArgument(0).(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_11(Variable vnew_path_223, EqualityOperation target_17, FunctionCall target_11) {
		target_11.getTarget().hasName("strlen")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vnew_path_223
		and target_11.getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_12(Variable vlen_222, BlockStmt target_14, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getLesserOperand().(Literal).getValue()="1"
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=vlen_222
		and target_12.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_12.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_14
}

predicate func_13(Variable vnew_path_223, EqualityOperation target_13) {
		target_13.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnew_path_223
		and target_13.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand() instanceof FunctionCall
		and target_13.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_13.getAnOperand().(CharLiteral).getValue()="34"
}

predicate func_14(Variable vlen_222, Variable vnew_path_223, BlockStmt target_14) {
		target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnew_path_223
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_222
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="0"
}

predicate func_15(Variable vlen_222, Variable vnew_path_223, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_222
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnew_path_223
}

predicate func_16(Variable vnew_path_223, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnew_path_223
		and target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand() instanceof FunctionCall
		and target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_16.getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="0"
}

predicate func_17(Variable vnew_path_223, EqualityOperation target_17) {
		target_17.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnew_path_223
		and target_17.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_17.getAnOperand().(CharLiteral).getValue()="47"
}

from Function func, Variable vlen_222, Variable vnew_path_223, EqualityOperation target_7, VariableAccess target_8, FunctionCall target_9, FunctionCall target_10, FunctionCall target_11, RelationalOperation target_12, EqualityOperation target_13, BlockStmt target_14, ExprStmt target_15, ExprStmt target_16, EqualityOperation target_17
where
not func_0(vlen_222)
and not func_3(vlen_222, vnew_path_223, target_13)
and not func_5(vlen_222, target_13)
and not func_6(vlen_222, target_14, target_15)
and func_7(vlen_222, vnew_path_223, target_14, target_7)
and func_8(vlen_222, target_8)
and func_9(vnew_path_223, target_13, target_9)
and func_10(vnew_path_223, target_16, target_10)
and func_11(vnew_path_223, target_17, target_11)
and func_12(vlen_222, target_14, target_12)
and func_13(vnew_path_223, target_13)
and func_14(vlen_222, vnew_path_223, target_14)
and func_15(vlen_222, vnew_path_223, target_15)
and func_16(vnew_path_223, target_16)
and func_17(vnew_path_223, target_17)
and vlen_222.getType().hasName("size_t")
and vnew_path_223.getType().hasName("char *")
and vlen_222.getParentScope+() = func
and vnew_path_223.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
