/**
 * @name ffmpeg-cb243972b121b1ae6b60a78ff55a0506c69f3879-xpm_decode_frame
 * @id cpp/ffmpeg/cb243972b121b1ae6b60a78ff55a0506c69f3879/xpm-decode-frame
 * @description ffmpeg-cb243972b121b1ae6b60a78ff55a0506c69f3879-libavcodec/xpmdec.c-xpm_decode_frame CVE-2017-9990
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="94"
		and not target_0.getValue()="95"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vavpkt_298, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="data"
		and target_1.getQualifier().(VariableAccess).getTarget()=vavpkt_298
}

predicate func_2(Parameter vavpkt_298, Variable vx_300) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("av_fast_padded_malloc")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_300
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf_size"
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_300
		and target_2.getArgument(2).(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298)
}

predicate func_3(Variable vx_300, BlockStmt target_44) {
	exists(NotExpr target_3 |
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_300
		and target_3.getParent().(IfStmt).getThen()=target_44)
}

predicate func_5(RelationalOperation target_41, Function func) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_5.getParent().(IfStmt).getCondition()=target_41
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vavpkt_298, Variable vx_300, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buf"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_300
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="size"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_6))
}

predicate func_7(Parameter vavpkt_298, Variable vx_300, ExprStmt target_45, ReturnStmt target_46, AddressOfExpr target_47, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="buf"
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_300
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="size"
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_7)
		and target_45.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_46.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_47.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Variable vx_300, Variable vptr_302, LogicalAndExpr target_48, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_302
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_300
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_8)
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_48.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_10(Variable vx_300) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="buf"
		and target_10.getQualifier().(VariableAccess).getTarget()=vx_300)
}

*/
predicate func_11(Parameter vavpkt_298, Variable vx_300, Variable vend_302, ExprStmt target_45, LogicalAndExpr target_48, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_302
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_300
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_11)
		and target_11.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_45.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_12(Variable vx_300) {
	exists(PointerFieldAccess target_12 |
		target_12.getTarget().getName()="buf"
		and target_12.getQualifier().(VariableAccess).getTarget()=vx_300)
}

*/
/*predicate func_13(Parameter vavpkt_298, ExprStmt target_45) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="size"
		and target_13.getQualifier().(VariableAccess).getTarget()=vavpkt_298
		and target_13.getQualifier().(VariableAccess).getLocation().isBefore(target_45.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_14(Variable vend_302, Variable vptr_302, ReturnStmt target_49, ExprStmt target_45, RelationalOperation target_41, LogicalAndExpr target_48, ExprStmt target_50) {
	exists(PointerArithmeticOperation target_14 |
		target_14.getLeftOperand().(VariableAccess).getTarget()=vend_302
		and target_14.getRightOperand().(VariableAccess).getTarget()=vptr_302
		and target_14.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_14.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vend_302
		and target_14.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_49
		and target_45.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getLeftOperand().(VariableAccess).getLocation())
		and target_14.getLeftOperand().(VariableAccess).getLocation().isBefore(target_41.getLesserOperand().(VariableAccess).getLocation())
		and target_48.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getRightOperand().(VariableAccess).getLocation())
		and target_14.getRightOperand().(VariableAccess).getLocation().isBefore(target_50.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_15(Variable vend_302, Variable vptr_302, ReturnStmt target_49, LogicalAndExpr target_48, RelationalOperation target_51, ExprStmt target_50, ExprStmt target_52) {
	exists(RelationalOperation target_15 |
		 (target_15 instanceof GEExpr or target_15 instanceof LEExpr)
		and target_15.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_302
		and target_15.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vptr_302
		and target_15.getGreaterOperand().(Literal).getValue()="9"
		and target_15.getParent().(IfStmt).getThen()=target_49
		and target_15.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_51.getLesserOperand().(VariableAccess).getLocation())
		and target_50.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_15.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_15.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_52.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_16(Variable vend_302, Variable vptr_302, RelationalOperation target_41, ExprStmt target_53, ExprStmt target_54, Function func) {
	exists(IfStmt target_16 |
		target_16.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_302
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vptr_302
		and target_16.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_16.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_16 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_16)
		and target_41.getLesserOperand().(VariableAccess).getLocation().isBefore(target_16.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_53.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_16.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_54.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_17(Variable vend_302, Variable vptr_302, RelationalOperation target_41, ExprStmt target_53, ExprStmt target_54) {
	exists(PointerArithmeticOperation target_17 |
		target_17.getLeftOperand().(VariableAccess).getTarget()=vend_302
		and target_17.getRightOperand().(VariableAccess).getTarget()=vptr_302
		and target_41.getLesserOperand().(VariableAccess).getLocation().isBefore(target_17.getLeftOperand().(VariableAccess).getLocation())
		and target_53.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_17.getRightOperand().(VariableAccess).getLocation())
		and target_17.getRightOperand().(VariableAccess).getLocation().isBefore(target_54.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

*/
predicate func_19(Variable vend_302, Variable vptr_302, Variable vcpp_303, ReturnStmt target_55, RelationalOperation target_56, RelationalOperation target_57, ExprStmt target_58) {
	exists(RelationalOperation target_19 |
		 (target_19 instanceof GTExpr or target_19 instanceof LTExpr)
		and target_19.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_302
		and target_19.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vptr_302
		and target_19.getGreaterOperand().(VariableAccess).getTarget()=vcpp_303
		and target_19.getParent().(IfStmt).getThen()=target_55
		and target_19.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_56.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_57.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_19.getGreaterOperand().(VariableAccess).getLocation())
		and target_19.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_58.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_20(Variable vend_302, Variable vptr_302, RelationalOperation target_51, ExprStmt target_59) {
	exists(IfStmt target_20 |
		target_20.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_302
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vptr_302
		and target_20.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_20.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_51.getLesserOperand().(VariableAccess).getLocation().isBefore(target_20.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_59.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_20.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_21(Variable vend_302, Variable vptr_302, ExprStmt target_60) {
	exists(IfStmt target_21 |
		target_21.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_302
		and target_21.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vptr_302
		and target_21.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_21.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_21.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_60.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_22(Variable vend_302, Variable vptr_302, ExprStmt target_60) {
	exists(IfStmt target_22 |
		target_22.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_302
		and target_22.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vptr_302
		and target_22.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_22.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_60.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_22.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_23(Variable vend_302, Variable vptr_302, Variable vcpp_303, RelationalOperation target_43, RelationalOperation target_61, RelationalOperation target_56) {
	exists(IfStmt target_23 |
		target_23.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_302
		and target_23.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vptr_302
		and target_23.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcpp_303
		and target_23.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_23.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_43.getLesserOperand().(VariableAccess).getLocation())
		and target_61.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_23.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_23.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_56.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_24(Parameter vavpkt_298, PointerFieldAccess target_24) {
		target_24.getTarget().getName()="data"
		and target_24.getQualifier().(VariableAccess).getTarget()=vavpkt_298
}

*/
/*predicate func_25(Parameter vavpkt_298, PointerFieldAccess target_25) {
		target_25.getTarget().getName()="size"
		and target_25.getQualifier().(VariableAccess).getTarget()=vavpkt_298
}

*/
predicate func_26(Parameter vavpkt_298, VariableAccess target_26) {
		target_26.getTarget()=vavpkt_298
}

predicate func_27(Parameter vavpkt_298, Variable vend_302, VariableAccess target_27) {
		target_27.getTarget()=vend_302
		and target_27.getParent().(AssignExpr).getLValue() = target_27
		and target_27.getParent().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_27.getParent().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298
		and target_27.getParent().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_27.getParent().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298
}

predicate func_28(Variable vend_302, VariableAccess target_28) {
		target_28.getTarget()=vend_302
}

predicate func_29(Variable vptr_302, VariableAccess target_29) {
		target_29.getTarget()=vptr_302
}

/*predicate func_31(Variable vend_302, Variable vptr_302, BlockStmt target_44, VariableAccess target_31) {
		target_31.getTarget()=vptr_302
		and target_31.getParent().(GEExpr).getLesserOperand().(VariableAccess).getTarget()=vend_302
		and target_31.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_44
}

*/
/*predicate func_32(Variable vend_302, Variable vptr_302, BlockStmt target_44, VariableAccess target_32) {
		target_32.getTarget()=vend_302
		and target_32.getParent().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vptr_302
		and target_32.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_44
}

*/
predicate func_33(Variable vptr_302, VariableAccess target_33) {
		target_33.getTarget()=vptr_302
}

predicate func_34(Variable vcpp_303, VariableAccess target_34) {
		target_34.getTarget()=vcpp_303
}

predicate func_35(Variable vend_302, ReturnStmt target_49, VariableAccess target_35) {
		target_35.getTarget()=vend_302
		and target_35.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_49
}

predicate func_36(Variable vptr_302, VariableAccess target_36) {
		target_36.getTarget()=vptr_302
}

predicate func_37(Variable vcpp_303, VariableAccess target_37) {
		target_37.getTarget()=vcpp_303
}

predicate func_38(Variable vend_302, ReturnStmt target_55, VariableAccess target_38) {
		target_38.getTarget()=vend_302
		and target_38.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_38.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_55
}

predicate func_39(Parameter vavpkt_298, Initializer target_39) {
		target_39.getExpr().(PointerFieldAccess).getTarget().getName()="data"
		and target_39.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298
}

predicate func_40(Variable vend_302, PointerArithmeticOperation target_40) {
		target_40.getLeftOperand().(VariableAccess).getTarget()=vend_302
		and target_40.getRightOperand() instanceof Literal
}

predicate func_41(Variable vend_302, Variable vptr_302, BlockStmt target_44, RelationalOperation target_41) {
		 (target_41 instanceof GEExpr or target_41 instanceof LEExpr)
		and target_41.getGreaterOperand().(VariableAccess).getTarget()=vptr_302
		and target_41.getLesserOperand().(VariableAccess).getTarget()=vend_302
		and target_41.getParent().(IfStmt).getThen()=target_44
}

predicate func_42(Variable vend_302, Variable vptr_302, Variable vcpp_303, ReturnStmt target_49, RelationalOperation target_41, ExprStmt target_53, ExprStmt target_54, RelationalOperation target_57, ExprStmt target_58, PointerArithmeticOperation target_42) {
		target_42.getAnOperand().(VariableAccess).getTarget()=vptr_302
		and target_42.getAnOperand().(VariableAccess).getTarget()=vcpp_303
		and target_42.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vend_302
		and target_42.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_49
		and target_41.getLesserOperand().(VariableAccess).getLocation().isBefore(target_42.getParent().(GTExpr).getLesserOperand().(VariableAccess).getLocation())
		and target_53.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_42.getAnOperand().(VariableAccess).getLocation())
		and target_42.getAnOperand().(VariableAccess).getLocation().isBefore(target_54.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_57.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_42.getAnOperand().(VariableAccess).getLocation())
		and target_42.getAnOperand().(VariableAccess).getLocation().isBefore(target_58.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_43(Variable vend_302, Variable vptr_302, Variable vcpp_303, ReturnStmt target_55, RelationalOperation target_43) {
		 (target_43 instanceof GTExpr or target_43 instanceof LTExpr)
		and target_43.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_302
		and target_43.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcpp_303
		and target_43.getLesserOperand().(VariableAccess).getTarget()=vend_302
		and target_43.getParent().(IfStmt).getThen()=target_55
}

predicate func_44(BlockStmt target_44) {
		target_44.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_44.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_44.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="missing signature\n"
		and target_44.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

predicate func_45(Parameter vavpkt_298, Variable vend_302, ExprStmt target_45) {
		target_45.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_302
		and target_45.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_45.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298
		and target_45.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_45.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298
}

predicate func_46(Parameter vavpkt_298, ReturnStmt target_46) {
		target_46.getExpr().(PointerFieldAccess).getTarget().getName()="size"
		and target_46.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavpkt_298
}

predicate func_47(Variable vx_300, AddressOfExpr target_47) {
		target_47.getOperand().(PointerFieldAccess).getTarget().getName()="pixels"
		and target_47.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_300
}

predicate func_48(Variable vptr_302, LogicalAndExpr target_48) {
		target_48.getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_48.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_302
		and target_48.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="/* XPM */"
		and target_48.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="9"
		and target_48.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vptr_302
		and target_48.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerArithmeticOperation
}

predicate func_49(ReturnStmt target_49) {
		target_49.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

predicate func_50(Variable vptr_302, ExprStmt target_50) {
		target_50.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vptr_302
}

predicate func_51(Variable vend_302, RelationalOperation target_51) {
		 (target_51 instanceof GTExpr or target_51 instanceof LTExpr)
		and target_51.getGreaterOperand() instanceof PointerArithmeticOperation
		and target_51.getLesserOperand().(VariableAccess).getTarget()=vend_302
}

predicate func_52(Variable vptr_302, ExprStmt target_52) {
		target_52.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_302
		and target_52.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getTarget().hasName("mod_strcspn")
		and target_52.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_302
		and target_52.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\""
}

predicate func_53(Variable vptr_302, ExprStmt target_53) {
		target_53.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_302
		and target_53.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("mod_strcspn")
		and target_53.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_302
		and target_53.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\""
		and target_53.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_54(Variable vptr_302, ExprStmt target_54) {
		target_54.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_302
}

predicate func_55(ReturnStmt target_55) {
		target_55.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

predicate func_56(Variable vptr_302, Variable vcpp_303, RelationalOperation target_56) {
		 (target_56 instanceof GTExpr or target_56 instanceof LTExpr)
		and target_56.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ascii2index")
		and target_56.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_302
		and target_56.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcpp_303
		and target_56.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_57(Variable vcpp_303, RelationalOperation target_57) {
		 (target_57 instanceof GTExpr or target_57 instanceof LTExpr)
		and target_57.getGreaterOperand().(VariableAccess).getTarget()=vcpp_303
}

predicate func_58(Variable vptr_302, Variable vcpp_303, ExprStmt target_58) {
		target_58.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_302
		and target_58.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vcpp_303
}

predicate func_59(Variable vptr_302, ExprStmt target_59) {
		target_59.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_302
		and target_59.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("mod_strcspn")
		and target_59.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_302
		and target_59.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=","
		and target_59.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_60(Variable vptr_302, ExprStmt target_60) {
		target_60.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_302
		and target_60.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("mod_strcspn")
		and target_60.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_302
		and target_60.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\""
		and target_60.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_61(Variable vcpp_303, RelationalOperation target_61) {
		 (target_61 instanceof GTExpr or target_61 instanceof LTExpr)
		and target_61.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ascii2index")
		and target_61.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcpp_303
		and target_61.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Parameter vavpkt_298, Variable vx_300, Variable vend_302, Variable vptr_302, Variable vcpp_303, Literal target_0, PointerFieldAccess target_1, VariableAccess target_26, VariableAccess target_27, VariableAccess target_28, VariableAccess target_29, VariableAccess target_33, VariableAccess target_34, VariableAccess target_35, VariableAccess target_36, VariableAccess target_37, VariableAccess target_38, Initializer target_39, PointerArithmeticOperation target_40, RelationalOperation target_41, PointerArithmeticOperation target_42, RelationalOperation target_43, BlockStmt target_44, ExprStmt target_45, ReturnStmt target_46, AddressOfExpr target_47, LogicalAndExpr target_48, ReturnStmt target_49, ExprStmt target_50, RelationalOperation target_51, ExprStmt target_52, ExprStmt target_53, ExprStmt target_54, ReturnStmt target_55, RelationalOperation target_56, RelationalOperation target_57, ExprStmt target_58, ExprStmt target_59, ExprStmt target_60, RelationalOperation target_61
where
func_0(func, target_0)
and func_1(vavpkt_298, target_1)
and not func_2(vavpkt_298, vx_300)
and not func_3(vx_300, target_44)
and not func_5(target_41, func)
and not func_6(vavpkt_298, vx_300, func)
and not func_7(vavpkt_298, vx_300, target_45, target_46, target_47, func)
and not func_8(vx_300, vptr_302, target_48, func)
and not func_11(vavpkt_298, vx_300, vend_302, target_45, target_48, func)
and not func_14(vend_302, vptr_302, target_49, target_45, target_41, target_48, target_50)
and not func_15(vend_302, vptr_302, target_49, target_48, target_51, target_50, target_52)
and not func_16(vend_302, vptr_302, target_41, target_53, target_54, func)
and not func_19(vend_302, vptr_302, vcpp_303, target_55, target_56, target_57, target_58)
and not func_20(vend_302, vptr_302, target_51, target_59)
and not func_21(vend_302, vptr_302, target_60)
and not func_22(vend_302, vptr_302, target_60)
and not func_23(vend_302, vptr_302, vcpp_303, target_43, target_61, target_56)
and func_26(vavpkt_298, target_26)
and func_27(vavpkt_298, vend_302, target_27)
and func_28(vend_302, target_28)
and func_29(vptr_302, target_29)
and func_33(vptr_302, target_33)
and func_34(vcpp_303, target_34)
and func_35(vend_302, target_49, target_35)
and func_36(vptr_302, target_36)
and func_37(vcpp_303, target_37)
and func_38(vend_302, target_55, target_38)
and func_39(vavpkt_298, target_39)
and func_40(vend_302, target_40)
and func_41(vend_302, vptr_302, target_44, target_41)
and func_42(vend_302, vptr_302, vcpp_303, target_49, target_41, target_53, target_54, target_57, target_58, target_42)
and func_43(vend_302, vptr_302, vcpp_303, target_55, target_43)
and func_44(target_44)
and func_45(vavpkt_298, vend_302, target_45)
and func_46(vavpkt_298, target_46)
and func_47(vx_300, target_47)
and func_48(vptr_302, target_48)
and func_49(target_49)
and func_50(vptr_302, target_50)
and func_51(vend_302, target_51)
and func_52(vptr_302, target_52)
and func_53(vptr_302, target_53)
and func_54(vptr_302, target_54)
and func_55(target_55)
and func_56(vptr_302, vcpp_303, target_56)
and func_57(vcpp_303, target_57)
and func_58(vptr_302, vcpp_303, target_58)
and func_59(vptr_302, target_59)
and func_60(vptr_302, target_60)
and func_61(vcpp_303, target_61)
and vavpkt_298.getType().hasName("AVPacket *")
and vx_300.getType().hasName("XPMDecContext *")
and vend_302.getType().hasName("const uint8_t *")
and vptr_302.getType().hasName("const uint8_t *")
and vcpp_303.getType().hasName("int")
and vavpkt_298.getParentScope+() = func
and vx_300.getParentScope+() = func
and vend_302.getParentScope+() = func
and vptr_302.getParentScope+() = func
and vcpp_303.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
