/**
 * @name linux-a54988113985ca22e414e132054f234fc8a92604-wcd9335_codec_enable_dec
 * @id cpp/linux/a54988113985ca22e414e132054f234fc8a92604/wcd9335_codec_enable_dec
 * @description linux-a54988113985ca22e414e132054f234fc8a92604-wcd9335_codec_enable_dec 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vw_2723) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("kstrndup")
		and not target_0.getTarget().hasName("kmemdup_nul")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vw_2723
		and target_0.getArgument(1).(Literal).getValue()="15"
		and target_0.getArgument(2).(BitwiseOrExpr).getValue()="3264"
		and target_0.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3136"
		and target_0.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3072"
		and target_0.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_0.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_0.getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_0.getArgument(2).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128")
}

from Function func, Parameter vw_2723
where
func_0(vw_2723)
and vw_2723.getType().hasName("snd_soc_dapm_widget *")
and vw_2723.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
