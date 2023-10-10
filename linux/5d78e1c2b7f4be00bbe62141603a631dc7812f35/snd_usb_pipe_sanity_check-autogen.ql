/**
 * @name linux-5d78e1c2b7f4be00bbe62141603a631dc7812f35-snd_usb_pipe_sanity_check
 * @id cpp/linux/5d78e1c2b7f4be00bbe62141603a631dc7812f35/snd_usb_pipe_sanity_check
 * @description linux-5d78e1c2b7f4be00bbe62141603a631dc7812f35-snd_usb_pipe_sanity_check 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vep_72) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vep_72
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

predicate func_1(Parameter vpipe_67, Variable vpipetypes_69, Variable vep_72) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vpipe_67
		and target_1.getAnOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="30"
		and target_1.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="3"
		and target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpipetypes_69
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(FunctionCall).getTarget().hasName("usb_endpoint_type")
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="desc"
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vep_72
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

predicate func_2(Parameter vpipe_67, Variable vep_72, Parameter vdev_67) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vep_72
		and target_2.getRValue().(FunctionCall).getTarget().hasName("usb_pipe_endpoint")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_67
		and target_2.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpipe_67)
}

from Function func, Parameter vpipe_67, Variable vpipetypes_69, Variable vep_72, Parameter vdev_67
where
not func_0(vep_72)
and func_1(vpipe_67, vpipetypes_69, vep_72)
and vpipe_67.getType().hasName("unsigned int")
and vpipetypes_69.getType().hasName("const int[4]")
and vep_72.getType().hasName("usb_host_endpoint *")
and func_2(vpipe_67, vep_72, vdev_67)
and vdev_67.getType().hasName("usb_device *")
and vpipe_67.getParentScope+() = func
and vpipetypes_69.getParentScope+() = func
and vep_72.getParentScope+() = func
and vdev_67.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
