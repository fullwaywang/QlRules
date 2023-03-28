/**
 * @name redis-1ddecf1958924b178b76a31d989ef1e05af81964-stralgoLCS
 * @id cpp/redis/1ddecf1958924b178b76a31d989ef1e05af81964/stralgoLCS
 * @description redis-1ddecf1958924b178b76a31d989ef1e05af81964-stralgoLCS CVE-2021-32625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("zmalloc")
		and not target_0.getTarget().hasName("ztrymalloc")
		and target_0.getArgument(0).(MulExpr).getLeftOperand() instanceof MulExpr
		and target_0.getArgument(0).(MulExpr).getRightOperand() instanceof SizeofTypeOperator
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vc_732, Variable va_735, Variable vb_735, ExprStmt target_9, EqualityOperation target_10, FunctionCall target_11, ExprStmt target_12, FunctionCall target_13, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_735
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967294"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_735
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967294"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_732
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="String too long for LCS"
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1)
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_10.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getArgument(0).(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Variable vlcs_811, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("unsigned long long")
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="18446744073709551615"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getType().hasName("unsigned long long")
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getType().hasName("unsigned long long")
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofTypeOperator).getValue()="4"
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlcs_811
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ztrymalloc")
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("unsigned long long")
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_4))
}

predicate func_6(Parameter vc_732, Variable vlcs_811, ExprStmt target_14, ExprStmt target_15, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vlcs_811
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_732
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Insufficient memory"
		and target_6.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_6)
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_7(Variable valen_805, Variable vblen_806, MulExpr target_7) {
		target_7.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=valen_805
		and target_7.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_7.getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vblen_806
		and target_7.getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_8(Function func, SizeofTypeOperator target_8) {
		target_8.getType() instanceof LongType
		and target_8.getValue()="4"
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Parameter vc_732, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_732
		and target_9.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="If you want both the length and indexes, please just use IDX."
}

predicate func_10(Variable va_735, EqualityOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=va_735
		and target_10.getAnOperand().(Literal).getValue()="0"
}

predicate func_11(Variable va_735, FunctionCall target_11) {
		target_11.getTarget().hasName("sdslen")
		and target_11.getArgument(0).(VariableAccess).getTarget()=va_735
}

predicate func_12(Variable vb_735, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vb_735
		and target_12.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ptr"
		and target_12.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("robj *")
}

predicate func_13(Variable vb_735, FunctionCall target_13) {
		target_13.getTarget().hasName("sdslen")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vb_735
}

predicate func_14(Parameter vc_732, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("addReplyMapLen")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_732
		and target_14.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
}

predicate func_15(Variable vblen_806, Variable vlcs_811, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlcs_811
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vblen_806
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_15.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vc_732, Variable va_735, Variable vb_735, Variable valen_805, Variable vblen_806, Variable vlcs_811, FunctionCall target_0, MulExpr target_7, SizeofTypeOperator target_8, ExprStmt target_9, EqualityOperation target_10, FunctionCall target_11, ExprStmt target_12, FunctionCall target_13, ExprStmt target_14, ExprStmt target_15
where
func_0(func, target_0)
and not func_1(vc_732, va_735, vb_735, target_9, target_10, target_11, target_12, target_13, func)
and not func_4(vlcs_811, func)
and not func_6(vc_732, vlcs_811, target_14, target_15, func)
and func_7(valen_805, vblen_806, target_7)
and func_8(func, target_8)
and func_9(vc_732, target_9)
and func_10(va_735, target_10)
and func_11(va_735, target_11)
and func_12(vb_735, target_12)
and func_13(vb_735, target_13)
and func_14(vc_732, target_14)
and func_15(vblen_806, vlcs_811, target_15)
and vc_732.getType().hasName("client *")
and va_735.getType().hasName("sds")
and vb_735.getType().hasName("sds")
and valen_805.getType().hasName("uint32_t")
and vblen_806.getType().hasName("uint32_t")
and vlcs_811.getType().hasName("uint32_t *")
and vc_732.getParentScope+() = func
and va_735.getParentScope+() = func
and vb_735.getParentScope+() = func
and valen_805.getParentScope+() = func
and vblen_806.getParentScope+() = func
and vlcs_811.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
