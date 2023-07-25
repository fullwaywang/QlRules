/**
 * @name jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_decode_gray_scale_image
 * @id cpp/jbig2dec/e698d5c11d27212aa1098bc5b1673a3378563092/jbig2-decode-gray-scale-image
 * @description jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_halftone.c-jbig2_decode_gray_scale_image CVE-2016-9601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vGSBPP_256, ArrayExpr target_39, RelationalOperation target_40, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="1"
		and target_0.getParent().(SubExpr).getParent().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vGSBPP_256
		and target_39.getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getParent().(SubExpr).getParent().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getParent().(SubExpr).getParent().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_40.getGreaterOperand().(VariableAccess).getLocation())
}

predicate func_6(Variable vi_1_260, Variable vj_1_260, EqualityOperation target_41) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(VariableAccess).getTarget()=vj_1_260
		and target_6.getRValue().(VariableAccess).getTarget()=vi_1_260
		and target_41.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_6.getRValue().(VariableAccess).getLocation()))
}

predicate func_7(Variable vj_1_260, BlockStmt target_43, RelationalOperation target_32) {
	exists(RelationalOperation target_7 |
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vj_1_260
		and target_7.getLesserOperand() instanceof Literal
		and target_7.getParent().(ForStmt).getStmt()=target_43
		and target_7.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_32.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_8(Variable vGSPLANES_262, Parameter vctx_253, EqualityOperation target_41, ArrayExpr target_16) {
	exists(ArrayExpr target_8 |
		target_8.getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_8.getArrayOffset() instanceof PrefixDecrExpr
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_image_release")
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_253
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof ArrayExpr
		and target_41.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_8.getArrayBase().(VariableAccess).getLocation())
		and target_8.getArrayBase().(VariableAccess).getLocation().isBefore(target_16.getArrayBase().(VariableAccess).getLocation()))
}

predicate func_9(Variable vj_1_260, Parameter vGSBPP_256, ArrayExpr target_16, ArrayExpr target_39, RelationalOperation target_40) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=vj_1_260
		and target_9.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vGSBPP_256
		and target_9.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_16.getArrayOffset().(VariableAccess).getLocation().isBefore(target_9.getLValue().(VariableAccess).getLocation())
		and target_39.getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_9.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_9.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_40.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_10(Variable vj_1_260, RelationalOperation target_34) {
	exists(RelationalOperation target_10 |
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=vj_1_260
		and target_10.getLesserOperand() instanceof Literal
		and target_10.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_34.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_11(Variable vj_1_260, PrefixDecrExpr target_15, ArrayExpr target_16) {
	exists(PostfixDecrExpr target_11 |
		target_11.getOperand().(VariableAccess).getTarget()=vj_1_260
		and target_15.getOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(VariableAccess).getLocation())
		and target_11.getOperand().(VariableAccess).getLocation().isBefore(target_16.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_12(Variable vi_1_260, Variable vj_1_260, ExprStmt target_46, ArrayExpr target_47) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(VariableAccess).getTarget()=vj_1_260
		and target_12.getRValue().(VariableAccess).getTarget()=vi_1_260
		and target_46.getExpr().(AssignXorExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_12.getRValue().(VariableAccess).getLocation())
		and target_47.getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_12.getLValue().(VariableAccess).getLocation()))
}

predicate func_13(Variable vj_1_260, BlockStmt target_49, RelationalOperation target_36) {
	exists(RelationalOperation target_13 |
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vj_1_260
		and target_13.getLesserOperand() instanceof Literal
		and target_13.getParent().(ForStmt).getStmt()=target_49
		and target_13.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_36.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_14(Variable vcode_260, Parameter vctx_253, Parameter vsegment_253, IfStmt target_14) {
		target_14.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcode_260
		and target_14.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_error")
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_253
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="number"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsegment_253
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="error decoding GSPLANES for halftone image"
		and target_14.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_14.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="cleanup"
}

predicate func_15(Variable vj_1_260, PrefixDecrExpr target_15) {
		target_15.getOperand().(VariableAccess).getTarget()=vj_1_260
}

predicate func_16(Variable vj_1_260, Variable vGSPLANES_262, Parameter vctx_253, ArrayExpr target_16) {
		target_16.getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_16.getArrayOffset().(VariableAccess).getTarget()=vj_1_260
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_image_release")
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_253
}

predicate func_17(Parameter vGB_stats_256, Variable vconsumed_bytes_259, Variable vj_1_260, Variable vcode_260, Variable vGSPLANES_262, Variable vrparams_263, Variable vas_265, Parameter vctx_253, Parameter vsegment_253, Parameter vdata_254, Parameter vsize_254, Parameter vGSMMR_255, IfStmt target_17) {
		target_17.getCondition().(VariableAccess).getTarget()=vGSMMR_255
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_260
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_decode_halftone_mmr")
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_253
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrparams_263
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_254
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vconsumed_bytes_259
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_254
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vconsumed_bytes_259
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_1_260
		and target_17.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconsumed_bytes_259
		and target_17.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_260
		and target_17.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_decode_generic_region")
		and target_17.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_253
		and target_17.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsegment_253
		and target_17.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrparams_263
		and target_17.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vas_265
		and target_17.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_17.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_1_260
		and target_17.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vGB_stats_256
}

predicate func_18(Variable vstride_1_260, Variable vGSPLANES_262, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstride_1_260
		and target_18.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="stride"
		and target_18.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_18.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_19(Variable vi_1_260, Variable vj_1_260, Variable vstride_1_260, Variable vGSPLANES_262, Parameter vGSH_255, ForStmt target_19) {
		target_19.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_1_260
		and target_19.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_19.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1_260
		and target_19.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vstride_1_260
		and target_19.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vGSH_255
		and target_19.getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_1_260
		and target_19.getStmt().(ExprStmt).getExpr().(AssignXorExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_19.getStmt().(ExprStmt).getExpr().(AssignXorExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_19.getStmt().(ExprStmt).getExpr().(AssignXorExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_1_260
		and target_19.getStmt().(ExprStmt).getExpr().(AssignXorExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1_260
		and target_19.getStmt().(ExprStmt).getExpr().(AssignXorExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_19.getStmt().(ExprStmt).getExpr().(AssignXorExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_19.getStmt().(ExprStmt).getExpr().(AssignXorExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1_260
}

predicate func_20(Variable vj_1_260, PrefixDecrExpr target_20) {
		target_20.getOperand().(VariableAccess).getTarget()=vj_1_260
}

predicate func_21(Variable vGSVALS_258, Variable vi_1_260, Parameter vctx_253, Parameter vGSH_255, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSVALS_258
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1_260
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_alloc")
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="allocator"
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_253
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vGSH_255
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="1"
}

predicate func_31(Variable vi_1_260, Variable vj_1_260, AssignExpr target_31) {
		target_31.getLValue().(VariableAccess).getTarget()=vj_1_260
		and target_31.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_1_260
		and target_31.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_32(Variable vj_1_260, BlockStmt target_43, RelationalOperation target_32) {
		 (target_32 instanceof GEExpr or target_32 instanceof LEExpr)
		and target_32.getGreaterOperand().(VariableAccess).getTarget()=vj_1_260
		and target_32.getLesserOperand() instanceof Literal
		and target_32.getParent().(ForStmt).getStmt()=target_43
}

predicate func_33(Variable vj_1_260, Parameter vGSBPP_256, AssignExpr target_33) {
		target_33.getLValue().(VariableAccess).getTarget()=vj_1_260
		and target_33.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vGSBPP_256
		and target_33.getRValue().(SubExpr).getRightOperand() instanceof Literal
}

predicate func_34(Variable vj_1_260, ArrayExpr target_51, RelationalOperation target_34) {
		 (target_34 instanceof GEExpr or target_34 instanceof LEExpr)
		and target_34.getGreaterOperand().(VariableAccess).getTarget()=vj_1_260
		and target_34.getLesserOperand() instanceof Literal
		and target_34.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_51.getArrayOffset().(VariableAccess).getLocation())
}

predicate func_35(Variable vi_1_260, Variable vj_1_260, EqualityOperation target_52, AssignExpr target_35) {
		target_35.getLValue().(VariableAccess).getTarget()=vj_1_260
		and target_35.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_1_260
		and target_35.getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_52.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_35.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
}

predicate func_36(Variable vj_1_260, BlockStmt target_49, RelationalOperation target_36) {
		 (target_36 instanceof GEExpr or target_36 instanceof LEExpr)
		and target_36.getGreaterOperand().(VariableAccess).getTarget()=vj_1_260
		and target_36.getLesserOperand() instanceof Literal
		and target_36.getParent().(ForStmt).getStmt()=target_49
}

predicate func_37(Variable vj_1_260, ArrayExpr target_54, PrefixDecrExpr target_37) {
		target_37.getOperand().(VariableAccess).getTarget()=vj_1_260
		and target_37.getOperand().(VariableAccess).getLocation().isBefore(target_54.getArrayOffset().(VariableAccess).getLocation())
}

predicate func_38(Variable vGSVALS_258, Variable vj_1_260, EqualityOperation target_52, ExprStmt target_55, PrefixDecrExpr target_37, VariableAccess target_38) {
		target_38.getTarget()=vj_1_260
		and target_38.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSVALS_258
		and target_52.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_38.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_38.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_55.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_37.getOperand().(VariableAccess).getLocation().isBefore(target_38.getLocation())
}

predicate func_39(Variable vGSPLANES_262, Parameter vGSBPP_256, ArrayExpr target_39) {
		target_39.getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_39.getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vGSBPP_256
		and target_39.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_40(Variable vj_1_260, Parameter vGSBPP_256, RelationalOperation target_40) {
		 (target_40 instanceof GTExpr or target_40 instanceof LTExpr)
		and target_40.getLesserOperand().(VariableAccess).getTarget()=vj_1_260
		and target_40.getGreaterOperand().(VariableAccess).getTarget()=vGSBPP_256
}

predicate func_41(Variable vi_1_260, Variable vGSPLANES_262, EqualityOperation target_41) {
		target_41.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_41.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1_260
		and target_41.getAnOperand().(Literal).getValue()="0"
}

predicate func_43(Parameter vctx_253, BlockStmt target_43) {
		target_43.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_image_release")
		and target_43.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_253
		and target_43.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof ArrayExpr
}

predicate func_46(Variable vi_1_260, Variable vj_1_260, Variable vGSPLANES_262, ExprStmt target_46) {
		target_46.getExpr().(AssignXorExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_46.getExpr().(AssignXorExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_46.getExpr().(AssignXorExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_1_260
		and target_46.getExpr().(AssignXorExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1_260
		and target_46.getExpr().(AssignXorExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_46.getExpr().(AssignXorExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_46.getExpr().(AssignXorExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vj_1_260
		and target_46.getExpr().(AssignXorExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_46.getExpr().(AssignXorExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1_260
}

predicate func_47(Variable vj_1_260, Variable vGSPLANES_262, ArrayExpr target_47) {
		target_47.getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_47.getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vj_1_260
		and target_47.getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_49(Variable vGSVALS_258, Variable vj_1_260, Parameter vctx_253, BlockStmt target_49) {
		target_49.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_free")
		and target_49.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="allocator"
		and target_49.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_253
		and target_49.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSVALS_258
		and target_49.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_1_260
}

predicate func_51(Variable vj_1_260, Variable vGSPLANES_262, ArrayExpr target_51) {
		target_51.getArrayBase().(VariableAccess).getTarget()=vGSPLANES_262
		and target_51.getArrayOffset().(VariableAccess).getTarget()=vj_1_260
}

predicate func_52(Variable vGSVALS_258, Variable vi_1_260, EqualityOperation target_52) {
		target_52.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vGSVALS_258
		and target_52.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1_260
		and target_52.getAnOperand().(Literal).getValue()="0"
}

predicate func_54(Variable vGSVALS_258, Variable vj_1_260, ArrayExpr target_54) {
		target_54.getArrayBase().(VariableAccess).getTarget()=vGSVALS_258
		and target_54.getArrayOffset().(VariableAccess).getTarget()=vj_1_260
}

predicate func_55(Variable vGSVALS_258, Parameter vctx_253, ExprStmt target_55) {
		target_55.getExpr().(FunctionCall).getTarget().hasName("jbig2_free")
		and target_55.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="allocator"
		and target_55.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_253
		and target_55.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vGSVALS_258
}

from Function func, Parameter vGB_stats_256, Variable vGSVALS_258, Variable vconsumed_bytes_259, Variable vi_1_260, Variable vj_1_260, Variable vcode_260, Variable vstride_1_260, Variable vGSPLANES_262, Variable vrparams_263, Variable vas_265, Parameter vctx_253, Parameter vsegment_253, Parameter vdata_254, Parameter vsize_254, Parameter vGSMMR_255, Parameter vGSH_255, Parameter vGSBPP_256, Literal target_0, IfStmt target_14, PrefixDecrExpr target_15, ArrayExpr target_16, IfStmt target_17, ExprStmt target_18, ForStmt target_19, PrefixDecrExpr target_20, ExprStmt target_21, AssignExpr target_31, RelationalOperation target_32, AssignExpr target_33, RelationalOperation target_34, AssignExpr target_35, RelationalOperation target_36, PrefixDecrExpr target_37, VariableAccess target_38, ArrayExpr target_39, RelationalOperation target_40, EqualityOperation target_41, BlockStmt target_43, ExprStmt target_46, ArrayExpr target_47, BlockStmt target_49, ArrayExpr target_51, EqualityOperation target_52, ArrayExpr target_54, ExprStmt target_55
where
func_0(vGSBPP_256, target_39, target_40, target_0)
and not func_6(vi_1_260, vj_1_260, target_41)
and not func_7(vj_1_260, target_43, target_32)
and not func_8(vGSPLANES_262, vctx_253, target_41, target_16)
and not func_9(vj_1_260, vGSBPP_256, target_16, target_39, target_40)
and not func_10(vj_1_260, target_34)
and not func_11(vj_1_260, target_15, target_16)
and not func_12(vi_1_260, vj_1_260, target_46, target_47)
and not func_13(vj_1_260, target_49, target_36)
and func_14(vcode_260, vctx_253, vsegment_253, target_14)
and func_15(vj_1_260, target_15)
and func_16(vj_1_260, vGSPLANES_262, vctx_253, target_16)
and func_17(vGB_stats_256, vconsumed_bytes_259, vj_1_260, vcode_260, vGSPLANES_262, vrparams_263, vas_265, vctx_253, vsegment_253, vdata_254, vsize_254, vGSMMR_255, target_17)
and func_18(vstride_1_260, vGSPLANES_262, target_18)
and func_19(vi_1_260, vj_1_260, vstride_1_260, vGSPLANES_262, vGSH_255, target_19)
and func_20(vj_1_260, target_20)
and func_21(vGSVALS_258, vi_1_260, vctx_253, vGSH_255, target_21)
and func_31(vi_1_260, vj_1_260, target_31)
and func_32(vj_1_260, target_43, target_32)
and func_33(vj_1_260, vGSBPP_256, target_33)
and func_34(vj_1_260, target_51, target_34)
and func_35(vi_1_260, vj_1_260, target_52, target_35)
and func_36(vj_1_260, target_49, target_36)
and func_37(vj_1_260, target_54, target_37)
and func_38(vGSVALS_258, vj_1_260, target_52, target_55, target_37, target_38)
and func_39(vGSPLANES_262, vGSBPP_256, target_39)
and func_40(vj_1_260, vGSBPP_256, target_40)
and func_41(vi_1_260, vGSPLANES_262, target_41)
and func_43(vctx_253, target_43)
and func_46(vi_1_260, vj_1_260, vGSPLANES_262, target_46)
and func_47(vj_1_260, vGSPLANES_262, target_47)
and func_49(vGSVALS_258, vj_1_260, vctx_253, target_49)
and func_51(vj_1_260, vGSPLANES_262, target_51)
and func_52(vGSVALS_258, vi_1_260, target_52)
and func_54(vGSVALS_258, vj_1_260, target_54)
and func_55(vGSVALS_258, vctx_253, target_55)
and vGB_stats_256.getType().hasName("Jbig2ArithCx *")
and vGSVALS_258.getType().hasName("uint8_t **")
and vconsumed_bytes_259.getType().hasName("size_t")
and vi_1_260.getType().hasName("int")
and vj_1_260.getType().hasName("int")
and vcode_260.getType().hasName("int")
and vstride_1_260.getType().hasName("int")
and vGSPLANES_262.getType().hasName("Jbig2Image **")
and vrparams_263.getType().hasName("Jbig2GenericRegionParams")
and vas_265.getType().hasName("Jbig2ArithState *")
and vctx_253.getType().hasName("Jbig2Ctx *")
and vsegment_253.getType().hasName("Jbig2Segment *")
and vdata_254.getType().hasName("const byte *")
and vsize_254.getType().hasName("const size_t")
and vGSMMR_255.getType().hasName("int")
and vGSH_255.getType().hasName("uint32_t")
and vGSBPP_256.getType().hasName("uint32_t")
and vGB_stats_256.getParentScope+() = func
and vGSVALS_258.getParentScope+() = func
and vconsumed_bytes_259.getParentScope+() = func
and vi_1_260.getParentScope+() = func
and vj_1_260.getParentScope+() = func
and vcode_260.getParentScope+() = func
and vstride_1_260.getParentScope+() = func
and vGSPLANES_262.getParentScope+() = func
and vrparams_263.getParentScope+() = func
and vas_265.getParentScope+() = func
and vctx_253.getParentScope+() = func
and vsegment_253.getParentScope+() = func
and vdata_254.getParentScope+() = func
and vsize_254.getParentScope+() = func
and vGSMMR_255.getParentScope+() = func
and vGSH_255.getParentScope+() = func
and vGSBPP_256.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
