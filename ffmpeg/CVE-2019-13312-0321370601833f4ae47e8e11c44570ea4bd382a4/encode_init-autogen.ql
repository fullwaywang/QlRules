/**
 * @name ffmpeg-0321370601833f4ae47e8e11c44570ea4bd382a4-encode_init
 * @id cpp/ffmpeg/0321370601833f4ae47e8e11c44570ea4bd382a4/encode-init
 * @description ffmpeg-0321370601833f4ae47e8e11c44570ea4bd382a4-libavcodec/zmbvenc.c-encode_init CVE-2019-13312
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vc_300, NotExpr target_28) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="fmt"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_28.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vc_300) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="bypp"
		and target_1.getQualifier().(VariableAccess).getTarget()=vc_300)
}

predicate func_3(Variable vc_300, ExprStmt target_30) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="fmt"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_30.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vc_300, AddressOfExpr target_31, ExprStmt target_32) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="bypp"
		and target_4.getQualifier().(VariableAccess).getTarget()=vc_300
		and target_31.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getQualifier().(VariableAccess).getLocation())
		and target_4.getQualifier().(VariableAccess).getLocation().isBefore(target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Variable vc_300, ExprStmt target_30) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="bypp"
		and target_6.getQualifier().(VariableAccess).getTarget()=vc_300
		and target_6.getQualifier().(VariableAccess).getLocation().isBefore(target_30.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Variable vc_300) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="bypp"
		and target_8.getQualifier().(VariableAccess).getTarget()=vc_300)
}

predicate func_10(Variable vc_300, Variable vi_302, ExprStmt target_33) {
	exists(MulExpr target_10 |
		target_10.getLeftOperand() instanceof MulExpr
		and target_10.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_10.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_10.getParent().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vi_302
		and target_10.getParent().(LEExpr).getGreaterOperand() instanceof MulExpr
		and target_10.getParent().(LEExpr).getParent().(ForStmt).getStmt()=target_33)
}

predicate func_11(Variable vi_302, ExprStmt target_33) {
	exists(AssignExpr target_11 |
		target_11.getLValue() instanceof ArrayExpr
		and target_11.getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vi_302
		and target_11.getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("log2")
		and target_11.getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vi_302
		and target_11.getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(DivExpr).getRightOperand().(MulExpr).getLeftOperand() instanceof MulExpr
		and target_11.getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(DivExpr).getRightOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_11.getRValue().(MulExpr).getRightOperand().(Literal).getValue()="256"
		and target_33.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation()))
}

/*predicate func_12(Variable vc_300, ExprStmt target_33, ExprStmt target_34) {
	exists(MulExpr target_12 |
		target_12.getLeftOperand() instanceof MulExpr
		and target_12.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_12.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_12.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_34.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_13(Variable vc_300, Function func) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="comp_size"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1024"
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="4"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_13 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_13))
}

/*predicate func_14(Parameter vavctx_298, Variable vc_300, ExprStmt target_35, ExprStmt target_32, NotExpr target_36) {
	exists(MulExpr target_14 |
		target_14.getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_14.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_298
		and target_14.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_14.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_35.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_36.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_15(Variable vc_300, Function func) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pstride"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_15.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand() instanceof AddExpr
		and target_15.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_15.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_15.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_15.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="-16"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_15 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_15))
}

/*predicate func_16(Variable vc_300, ExprStmt target_30) {
	exists(MulExpr target_16 |
		target_16.getLeftOperand() instanceof AddExpr
		and target_16.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_16.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_30.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_17(Variable vc_300, Variable vprev_size_304, ExprStmt target_37, ExprStmt target_38, NotExpr target_39, Function func) {
	exists(ExprStmt target_17 |
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprev_size_304
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="-16"
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="pstride"
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="urange"
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_17 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_17)
		and target_37.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_38.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_39.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_18(Variable vc_300, ExprStmt target_37) {
	exists(BitwiseAndExpr target_18 |
		target_18.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_18.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_18.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_18.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_18.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_18.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_18.getRightOperand().(ComplementExpr).getValue()="-16"
		and target_18.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_37.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_19(Variable vc_300, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="comp_size"
		and target_19.getQualifier().(VariableAccess).getTarget()=vc_300
		and target_19.getParent().(AssignExpr).getLValue() = target_19
		and target_19.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_19.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_19.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1024"
		and target_19.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_19.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="4"
}

/*predicate func_20(Parameter vavctx_298, PointerFieldAccess target_20) {
		target_20.getTarget().getName()="width"
		and target_20.getQualifier().(VariableAccess).getTarget()=vavctx_298
}

*/
predicate func_21(Variable vc_300, PointerFieldAccess target_21) {
		target_21.getTarget().getName()="pstride"
		and target_21.getQualifier().(VariableAccess).getTarget()=vc_300
		and target_21.getParent().(AssignExpr).getLValue() = target_21
		and target_21.getParent().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_21.getParent().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_21.getParent().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_21.getParent().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_21.getParent().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="-16"
}

/*predicate func_22(Variable vc_300, BitwiseAndExpr target_22) {
		target_22.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_22.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_22.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_22.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_22.getRightOperand().(ComplementExpr).getValue()="-16"
}

*/
predicate func_23(Variable vi_302, ExprStmt target_33, MulExpr target_23) {
		target_23.getValue()="256"
		and target_23.getParent().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vi_302
		and target_23.getParent().(LEExpr).getParent().(ForStmt).getStmt()=target_33
}

/*predicate func_24(Function func, MulExpr target_24) {
		target_24.getValue()="256"
		and target_24.getEnclosingFunction() = func
}

*/
/*predicate func_25(Parameter vavctx_298, Variable vc_300, AddExpr target_25) {
		target_25.getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_25.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_298
		and target_25.getAnOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_25.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
}

*/
predicate func_26(Variable vc_300, Variable vi_302, ArrayExpr target_26) {
		target_26.getArrayBase().(PointerFieldAccess).getTarget().getName()="score_tab"
		and target_26.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_26.getArrayOffset().(VariableAccess).getTarget()=vi_302
		and target_26.getParent().(AssignExpr).getLValue() = target_26
		and target_26.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vi_302
		and target_26.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("log2")
		and target_26.getParent().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vi_302
		and target_26.getParent().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="256"
}

predicate func_27(Variable vc_300, Variable vprev_size_304, VariableAccess target_27) {
		target_27.getTarget()=vprev_size_304
		and target_27.getParent().(AssignExpr).getLValue() = target_27
		and target_27.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_27.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_27.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_27.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="-16"
		and target_27.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="pstride"
		and target_27.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_27.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_27.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_27.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="urange"
		and target_27.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
}

predicate func_28(Variable vc_300, NotExpr target_28) {
		target_28.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="comp_buf"
		and target_28.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_28.getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_28.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="comp_size"
		and target_28.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
}

predicate func_30(Variable vc_300, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pstride"
		and target_30.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_30.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof AddExpr
		and target_30.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_30.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_30.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="-16"
}

predicate func_31(Variable vc_300, AddressOfExpr target_31) {
		target_31.getOperand().(PointerFieldAccess).getTarget().getName()="zstream"
		and target_31.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
}

predicate func_32(Variable vc_300, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="comp_size"
		and target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_32.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_32.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_32.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1024"
		and target_32.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_32.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="4"
}

predicate func_33(Variable vi_302, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue() instanceof ArrayExpr
		and target_33.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vi_302
		and target_33.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("log2")
		and target_33.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vi_302
		and target_33.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(DivExpr).getRightOperand() instanceof MulExpr
		and target_33.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="256"
}

predicate func_34(Parameter vavctx_298, Variable vc_300, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_34.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_34.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vavctx_298
}

predicate func_35(Parameter vavctx_298, ExprStmt target_35) {
		target_35.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_35.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_298
		and target_35.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_35.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Compression level should be 0-9, not %i\n"
}

predicate func_36(Variable vc_300, NotExpr target_36) {
		target_36.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="work_buf"
		and target_36.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_36.getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_36.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="comp_size"
		and target_36.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
}

predicate func_37(Variable vc_300, Variable vprev_size_304, ExprStmt target_37) {
		target_37.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprev_size_304
		and target_37.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand() instanceof BitwiseAndExpr
		and target_37.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="pstride"
		and target_37.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_37.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_37.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_37.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="urange"
		and target_37.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
}

predicate func_38(Variable vc_300, ExprStmt target_38) {
		target_38.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_38.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_38.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_38.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="-16"
		and target_38.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="pstride"
		and target_38.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_38.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_38.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
}

predicate func_39(Variable vc_300, Variable vprev_size_304, NotExpr target_39) {
		target_39.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="prev_buf"
		and target_39.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_300
		and target_39.getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_mallocz")
		and target_39.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprev_size_304
}

from Function func, Parameter vavctx_298, Variable vc_300, Variable vi_302, Variable vprev_size_304, PointerFieldAccess target_19, PointerFieldAccess target_21, MulExpr target_23, ArrayExpr target_26, VariableAccess target_27, NotExpr target_28, ExprStmt target_30, AddressOfExpr target_31, ExprStmt target_32, ExprStmt target_33, ExprStmt target_34, ExprStmt target_35, NotExpr target_36, ExprStmt target_37, ExprStmt target_38, NotExpr target_39
where
not func_0(vc_300, target_28)
and not func_1(vc_300)
and not func_3(vc_300, target_30)
and not func_4(vc_300, target_31, target_32)
and not func_6(vc_300, target_30)
and not func_8(vc_300)
and not func_10(vc_300, vi_302, target_33)
and not func_11(vi_302, target_33)
and not func_13(vc_300, func)
and not func_15(vc_300, func)
and not func_17(vc_300, vprev_size_304, target_37, target_38, target_39, func)
and func_19(vc_300, target_19)
and func_21(vc_300, target_21)
and func_23(vi_302, target_33, target_23)
and func_26(vc_300, vi_302, target_26)
and func_27(vc_300, vprev_size_304, target_27)
and func_28(vc_300, target_28)
and func_30(vc_300, target_30)
and func_31(vc_300, target_31)
and func_32(vc_300, target_32)
and func_33(vi_302, target_33)
and func_34(vavctx_298, vc_300, target_34)
and func_35(vavctx_298, target_35)
and func_36(vc_300, target_36)
and func_37(vc_300, vprev_size_304, target_37)
and func_38(vc_300, target_38)
and func_39(vc_300, vprev_size_304, target_39)
and vavctx_298.getType().hasName("AVCodecContext *")
and vc_300.getType().hasName("ZmbvEncContext *const")
and vi_302.getType().hasName("int")
and vprev_size_304.getType().hasName("int")
and vavctx_298.getParentScope+() = func
and vc_300.getParentScope+() = func
and vi_302.getParentScope+() = func
and vprev_size_304.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
