/**
 * @name openssh-391ffc4b9d31fa1f4ad566499fef9176ff8a07dc-sink
 * @id cpp/openssh/391ffc4b9d31fa1f4ad566499fef9176ff8a07dc/sink
 * @description openssh-391ffc4b9d31fa1f4ad566499fef9176ff8a07dc-scp.c-sink CVE-2019-6111
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("const char *")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strdup")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const char *")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fatal")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="strdup failed"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strrchr")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="47"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_0))
}

/*predicate func_1(EqualityOperation target_9, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strdup")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const char *")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fatal")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="strdup failed"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_1.getEnclosingFunction() = func)
}

*/
/*predicate func_2(EqualityOperation target_9, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strrchr")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="47"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_2.getEnclosingFunction() = func)
}

*/
/*predicate func_3(Function func) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_3.getRValue().(CharLiteral).getValue()="0"
		and target_3.getEnclosingFunction() = func)
}

*/
predicate func_4(Variable vcp_989, BlockStmt target_19, ExprStmt target_20) {
	exists(LogicalAndExpr target_4 |
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("char *")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("fnmatch")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcp_989
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen()=target_19
		and target_20.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_5(Variable vwhy_989, EqualityOperation target_9, ExprStmt target_21) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwhy_989
		and target_5.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="filename does not match request"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_6(EqualityOperation target_9, Function func) {
	exists(GotoStmt target_6 |
		target_6.toString() = "goto ..."
		and target_6.getName() ="screwup"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vvect_989, ExprStmt target_13, ArrayExpr target_22) {
	exists(IfStmt target_7 |
		target_7.getCondition() instanceof EqualityOperation
		and target_7.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_7.getThen().(BlockStmt).getStmt(2).(EmptyStmt).toString() = ";"
		and target_7.getThen().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_7.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_7.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sink")
		and target_7.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_7.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvect_989
		and target_7.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("const char *")
		and target_7.getThen().(BlockStmt).getStmt(6) instanceof IfStmt
		and target_7.getThen().(BlockStmt).getStmt(7) instanceof IfStmt
		and target_7.getThen().(BlockStmt).getStmt(8) instanceof ExprStmt
		and target_7.getThen().(BlockStmt).getStmt(9) instanceof ContinueStmt
		and target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_7.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_7.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_22.getArrayBase().(VariableAccess).getLocation()))
}

predicate func_9(Variable vbuf_989, BlockStmt target_19, EqualityOperation target_9) {
		target_9.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_989
		and target_9.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_9.getAnOperand().(CharLiteral).getValue()="68"
		and target_9.getParent().(IfStmt).getThen()=target_19
}

predicate func_10(EqualityOperation target_9, Function func, DeclStmt target_10) {
		target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Variable vwhy_989, Variable viamrecursive, EqualityOperation target_9, IfStmt target_11) {
		target_11.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=viamrecursive
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwhy_989
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="received directory without -r"
		and target_11.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_11.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="screwup"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_12(Variable vexists_984, Variable vmode_985, Variable vnp_989, Variable vpflag, Variable vmod_flag_1137, EqualityOperation target_9, IfStmt target_12) {
		target_12.getCondition().(VariableAccess).getTarget()=vexists_984
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="st_mode"
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="16384"
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="20"
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_12.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="bad"
		and target_12.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vpflag
		and target_12.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("chmod")
		and target_12.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnp_989
		and target_12.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmode_985
		and target_12.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmod_flag_1137
		and target_12.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_12.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("mkdir")
		and target_12.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnp_989
		and target_12.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(VariableAccess).getTarget()=vmode_985
		and target_12.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_12.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_12.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).getName() ="bad"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_13(Variable vnp_989, Variable vvect_989, EqualityOperation target_9, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvect_989
		and target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xstrdup")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnp_989
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_14(Variable vsetimes_988, Variable vvect_989, Variable vtv_990, EqualityOperation target_9, IfStmt target_14) {
		target_14.getCondition().(VariableAccess).getTarget()=vsetimes_988
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsetimes_988
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("utimes")
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvect_989
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtv_990
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("run_err")
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s: set times: %s"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvect_989
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strerror")
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_15(Variable vmode_985, Variable vvect_989, Variable vmod_flag_1137, EqualityOperation target_9, IfStmt target_15) {
		target_15.getCondition().(VariableAccess).getTarget()=vmod_flag_1137
		and target_15.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("chmod")
		and target_15.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvect_989
		and target_15.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_15.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmode_985
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_16(Variable vvect_989, EqualityOperation target_9, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_16.getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvect_989
		and target_16.getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_17(EqualityOperation target_9, Function func, EmptyStmt target_17) {
		target_17.toString() = ";"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_17.getEnclosingFunction() = func
}

predicate func_18(EqualityOperation target_9, Function func, ContinueStmt target_18) {
		target_18.toString() = "continue;"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_18.getEnclosingFunction() = func
}

predicate func_19(Variable vvect_989, BlockStmt target_19) {
		target_19.getStmt(1) instanceof IfStmt
		and target_19.getStmt(2) instanceof EmptyStmt
		and target_19.getStmt(3) instanceof IfStmt
		and target_19.getStmt(4) instanceof ExprStmt
		and target_19.getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sink")
		and target_19.getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_19.getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvect_989
}

predicate func_20(Variable vcp_989, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcp_989
}

predicate func_21(Variable vwhy_989, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwhy_989
		and target_21.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="size out of range"
}

predicate func_22(Variable vvect_989, ArrayExpr target_22) {
		target_22.getArrayBase().(VariableAccess).getTarget()=vvect_989
		and target_22.getArrayOffset().(Literal).getValue()="0"
}

from Function func, Variable vexists_984, Variable vmode_985, Variable vsetimes_988, Variable vcp_989, Variable vnp_989, Variable vwhy_989, Variable vvect_989, Variable vbuf_989, Variable vtv_990, Variable vpflag, Variable viamrecursive, Variable vmod_flag_1137, EqualityOperation target_9, DeclStmt target_10, IfStmt target_11, IfStmt target_12, ExprStmt target_13, IfStmt target_14, IfStmt target_15, ExprStmt target_16, EmptyStmt target_17, ContinueStmt target_18, BlockStmt target_19, ExprStmt target_20, ExprStmt target_21, ArrayExpr target_22
where
not func_0(func)
and not func_4(vcp_989, target_19, target_20)
and not func_5(vwhy_989, target_9, target_21)
and not func_6(target_9, func)
and not func_7(vvect_989, target_13, target_22)
and func_9(vbuf_989, target_19, target_9)
and func_10(target_9, func, target_10)
and func_11(vwhy_989, viamrecursive, target_9, target_11)
and func_12(vexists_984, vmode_985, vnp_989, vpflag, vmod_flag_1137, target_9, target_12)
and func_13(vnp_989, vvect_989, target_9, target_13)
and func_14(vsetimes_988, vvect_989, vtv_990, target_9, target_14)
and func_15(vmode_985, vvect_989, vmod_flag_1137, target_9, target_15)
and func_16(vvect_989, target_9, target_16)
and func_17(target_9, func, target_17)
and func_18(target_9, func, target_18)
and func_19(vvect_989, target_19)
and func_20(vcp_989, target_20)
and func_21(vwhy_989, target_21)
and func_22(vvect_989, target_22)
and vexists_984.getType().hasName("int")
and vmode_985.getType().hasName("mode_t")
and vsetimes_988.getType().hasName("int")
and vcp_989.getType().hasName("char *")
and vnp_989.getType().hasName("char *")
and vwhy_989.getType().hasName("char *")
and vvect_989.getType().hasName("char *[1]")
and vbuf_989.getType().hasName("char[2048]")
and vtv_990.getType().hasName("timeval[2]")
and vpflag.getType().hasName("int")
and viamrecursive.getType().hasName("int")
and vmod_flag_1137.getType().hasName("int")
and vexists_984.getParentScope+() = func
and vmode_985.getParentScope+() = func
and vsetimes_988.getParentScope+() = func
and vcp_989.getParentScope+() = func
and vnp_989.getParentScope+() = func
and vwhy_989.getParentScope+() = func
and vvect_989.getParentScope+() = func
and vbuf_989.getParentScope+() = func
and vtv_990.getParentScope+() = func
and not vpflag.getParentScope+() = func
and not viamrecursive.getParentScope+() = func
and vmod_flag_1137.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
