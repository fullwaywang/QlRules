/**
 * @name linux-4071bf121d59944d5cd2238de0642f3d7995a997-nfc_genl_fw_download_done
 * @id cpp/linux/4071bf121d59944d5cd2238de0642f3d7995a997/nfc-genl-fw-download-done
 * @description linux-4071bf121d59944d5cd2238de0642f3d7995a997-nfc_genl_fw_download_done 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_10(Function func) {
	exists(BitwiseOrExpr target_10 |
		target_10.getValue()="3264"
		and target_10.getLeftOperand() instanceof BitwiseOrExpr
		and target_10.getRightOperand().(Literal).getValue()="128"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("nlmsg_new")
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getValue()="3760"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getValue()="3776"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="320"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="6"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="6"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(BitwiseAndExpr).getValue()="16"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="16"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="4"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(Literal).getValue()="4"
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_10.getEnclosingFunction() = func)
}

from Function func, Variable vmsg_1244, Variable vnfc_genl_family
where
func_10(func)
and vmsg_1244.getType().hasName("sk_buff *")
and vnfc_genl_family.getType().hasName("genl_family")
and vmsg_1244.getParentScope+() = func
and not vnfc_genl_family.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
