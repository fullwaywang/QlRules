/**
 * @name linux-daac07156b330b18eb5071aec4b3ddca1c377f2c-uac_mixer_unit_get_channels
 * @id cpp/linux/daac07156b330b18eb5071aec4b3ddca1c377f2c/uac_mixer_unit_get_channels
 * @description linux-daac07156b330b18eb5071aec4b3ddca1c377f2c-uac_mixer_unit_get_channels 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdesc_738, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="bLength"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_738
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(SizeofExprOperator).getValue()="5"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdesc_738
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="bNrInPins"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_738
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vdesc_738) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="bNrInPins"
		and target_1.getQualifier().(VariableAccess).getTarget()=vdesc_738)
}

from Function func, Parameter vdesc_738
where
not func_0(vdesc_738, func)
and vdesc_738.getType().hasName("uac_mixer_unit_descriptor *")
and func_1(vdesc_738)
and vdesc_738.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
