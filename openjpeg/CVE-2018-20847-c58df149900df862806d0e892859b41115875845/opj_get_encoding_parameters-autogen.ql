/**
 * @name openjpeg-c58df149900df862806d0e892859b41115875845-opj_get_encoding_parameters
 * @id cpp/openjpeg/c58df149900df862806d0e892859b41115875845/opj-get-encoding-parameters
 * @description openjpeg-c58df149900df862806d0e892859b41115875845-src/lib/openjp2/pi.c-opj_get_encoding_parameters CVE-2018-20847
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_749, VariableAccess target_0) {
		target_0.getTarget()=vp_749
}

predicate func_1(Variable vq_749, VariableAccess target_1) {
		target_1.getTarget()=vq_749
}

predicate func_2(Function func) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_2.getRValue() instanceof AddExpr
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vp_image_729, ExprStmt target_22) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("opj_uint_max")
		and target_3.getArgument(0).(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="x0"
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
		and target_22.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vp_cp_730, Parameter vp_image_729, AddExpr target_24, AddExpr target_14) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("opj_uint_min")
		and target_4.getArgument(0).(FunctionCall).getTarget().hasName("opj_uint_adds")
		and target_4.getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_4.getArgument(0).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdx"
		and target_4.getArgument(0).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_4.getArgument(1).(PointerFieldAccess).getTarget().getName()="x1"
		and target_4.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
		and target_24.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getArgument(0).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Function func) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_5.getRValue() instanceof AddExpr
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vp_ty0_734, Parameter vp_image_729, PointerDereferenceExpr target_27, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_ty0_734
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("opj_uint_max")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="y0"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_6)
		and target_6.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_27.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_7(Parameter vp_image_729) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("opj_uint_max")
		and target_7.getArgument(0).(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_7.getArgument(1).(PointerFieldAccess).getTarget().getName()="y0"
		and target_7.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729)
}

*/
predicate func_8(Parameter vp_cp_730, Parameter vp_image_729, Parameter vp_ty1_735, AddExpr target_32, RelationalOperation target_34, PointerDereferenceExpr target_35, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_ty1_735
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("opj_uint_min")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("opj_uint_adds")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdy"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="y1"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_8)
		and target_32.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_34.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_35.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_9(Parameter vp_cp_730, Parameter vp_image_729, AddExpr target_32, RelationalOperation target_34) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("opj_uint_min")
		and target_9.getArgument(0).(FunctionCall).getTarget().hasName("opj_uint_adds")
		and target_9.getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_9.getArgument(0).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdy"
		and target_9.getArgument(0).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_9.getArgument(1).(PointerFieldAccess).getTarget().getName()="y1"
		and target_9.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
		and target_32.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getArgument(0).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_34.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_10(Parameter vp_cp_730, Variable vp_749, AddExpr target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="tx0"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_10.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vp_749
		and target_10.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tdx"
		and target_10.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_11(Parameter vp_image_729, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="x0"
		and target_11.getQualifier().(VariableAccess).getTarget()=vp_image_729
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_12(Parameter vp_cp_730, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="tdx"
		and target_12.getQualifier().(VariableAccess).getTarget()=vp_cp_730
}

predicate func_13(Parameter vp_image_729, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="x1"
		and target_13.getQualifier().(VariableAccess).getTarget()=vp_image_729
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_14(Parameter vp_cp_730, Variable vq_749, AddExpr target_14) {
		target_14.getAnOperand().(PointerFieldAccess).getTarget().getName()="ty0"
		and target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_14.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vq_749
		and target_14.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tdy"
		and target_14.getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_14.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_15(Parameter vp_image_729, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="y0"
		and target_15.getQualifier().(VariableAccess).getTarget()=vp_image_729
		and target_15.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_16(Parameter vp_cp_730, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="tdy"
		and target_16.getQualifier().(VariableAccess).getTarget()=vp_cp_730
}

predicate func_17(Parameter vp_image_729, PointerFieldAccess target_17) {
		target_17.getTarget().getName()="y1"
		and target_17.getQualifier().(VariableAccess).getTarget()=vp_image_729
		and target_17.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_18(Parameter vp_image_729, FunctionCall target_18) {
		target_18.getTarget().hasName("opj_int_max")
		and target_18.getArgument(0) instanceof AddExpr
		and target_18.getArgument(1).(PointerFieldAccess).getTarget().getName()="x0"
		and target_18.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
}

predicate func_19(Parameter vp_cp_730, Parameter vp_image_729, Variable vp_749, FunctionCall target_19) {
		target_19.getTarget().hasName("opj_int_min")
		and target_19.getArgument(0).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tx0"
		and target_19.getArgument(0).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_19.getArgument(0).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vp_749
		and target_19.getArgument(0).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_19.getArgument(0).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tdx"
		and target_19.getArgument(0).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_19.getArgument(1).(PointerFieldAccess).getTarget().getName()="x1"
		and target_19.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
}

predicate func_20(Parameter vp_image_729, FunctionCall target_20) {
		target_20.getTarget().hasName("opj_int_max")
		and target_20.getArgument(0) instanceof AddExpr
		and target_20.getArgument(1).(PointerFieldAccess).getTarget().getName()="y0"
		and target_20.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
}

predicate func_21(Parameter vp_cp_730, Parameter vp_image_729, Variable vq_749, FunctionCall target_21) {
		target_21.getTarget().hasName("opj_int_min")
		and target_21.getArgument(0).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="ty0"
		and target_21.getArgument(0).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_21.getArgument(0).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vq_749
		and target_21.getArgument(0).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_21.getArgument(0).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="tdy"
		and target_21.getArgument(0).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_21.getArgument(1).(PointerFieldAccess).getTarget().getName()="y1"
		and target_21.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
}

predicate func_22(Parameter vp_image_729, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="comps"
		and target_22.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
}

predicate func_24(Parameter vp_cp_730, AddExpr target_24) {
		target_24.getAnOperand().(PointerFieldAccess).getTarget().getName()="tx0"
		and target_24.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_24.getAnOperand() instanceof MulExpr
}

predicate func_27(Parameter vp_ty0_734, PointerDereferenceExpr target_27) {
		target_27.getOperand().(VariableAccess).getTarget()=vp_ty0_734
}

predicate func_32(Parameter vp_cp_730, AddExpr target_32) {
		target_32.getAnOperand().(PointerFieldAccess).getTarget().getName()="ty0"
		and target_32.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_cp_730
		and target_32.getAnOperand() instanceof MulExpr
}

predicate func_34(Parameter vp_image_729, RelationalOperation target_34) {
		 (target_34 instanceof GTExpr or target_34 instanceof LTExpr)
		and target_34.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="numcomps"
		and target_34.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_image_729
}

predicate func_35(Parameter vp_ty1_735, PointerDereferenceExpr target_35) {
		target_35.getOperand().(VariableAccess).getTarget()=vp_ty1_735
}

from Function func, Parameter vp_cp_730, Parameter vp_ty0_734, Parameter vp_image_729, Parameter vp_ty1_735, Variable vp_749, Variable vq_749, VariableAccess target_0, VariableAccess target_1, AddExpr target_10, PointerFieldAccess target_11, PointerFieldAccess target_12, PointerFieldAccess target_13, AddExpr target_14, PointerFieldAccess target_15, PointerFieldAccess target_16, PointerFieldAccess target_17, FunctionCall target_18, FunctionCall target_19, FunctionCall target_20, FunctionCall target_21, ExprStmt target_22, AddExpr target_24, PointerDereferenceExpr target_27, AddExpr target_32, RelationalOperation target_34, PointerDereferenceExpr target_35
where
func_0(vp_749, target_0)
and func_1(vq_749, target_1)
and not func_2(func)
and not func_3(vp_image_729, target_22)
and not func_4(vp_cp_730, vp_image_729, target_24, target_14)
and not func_5(func)
and not func_6(vp_ty0_734, vp_image_729, target_27, func)
and not func_8(vp_cp_730, vp_image_729, vp_ty1_735, target_32, target_34, target_35, func)
and func_10(vp_cp_730, vp_749, target_10)
and func_11(vp_image_729, target_11)
and func_12(vp_cp_730, target_12)
and func_13(vp_image_729, target_13)
and func_14(vp_cp_730, vq_749, target_14)
and func_15(vp_image_729, target_15)
and func_16(vp_cp_730, target_16)
and func_17(vp_image_729, target_17)
and func_18(vp_image_729, target_18)
and func_19(vp_cp_730, vp_image_729, vp_749, target_19)
and func_20(vp_image_729, target_20)
and func_21(vp_cp_730, vp_image_729, vq_749, target_21)
and func_22(vp_image_729, target_22)
and func_24(vp_cp_730, target_24)
and func_27(vp_ty0_734, target_27)
and func_32(vp_cp_730, target_32)
and func_34(vp_image_729, target_34)
and func_35(vp_ty1_735, target_35)
and vp_cp_730.getType().hasName("const opj_cp_t *")
and vp_ty0_734.getType().hasName("OPJ_INT32 *")
and vp_image_729.getType().hasName("const opj_image_t *")
and vp_ty1_735.getType().hasName("OPJ_INT32 *")
and vp_749.getType().hasName("OPJ_UINT32")
and vq_749.getType().hasName("OPJ_UINT32")
and vp_cp_730.getParentScope+() = func
and vp_ty0_734.getParentScope+() = func
and vp_image_729.getParentScope+() = func
and vp_ty1_735.getParentScope+() = func
and vp_749.getParentScope+() = func
and vq_749.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
