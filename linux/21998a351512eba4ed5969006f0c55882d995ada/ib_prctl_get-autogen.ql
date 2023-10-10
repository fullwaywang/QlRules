/**
 * @name linux-21998a351512eba4ed5969006f0c55882d995ada-ib_prctl_get
 * @id cpp/linux/21998a351512eba4ed5969006f0c55882d995ada/ib_prctl_get
 * @description linux-21998a351512eba4ed5969006f0c55882d995ada-ib_prctl_get 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vspectre_v2_user) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vspectre_v2_user)
}

predicate func_1(Parameter vtask_1245, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getThen() instanceof ReturnStmt
		and target_1.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_1.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_1.getElse().(IfStmt).getThen() instanceof ReturnStmt
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("spectre_v2_user_mitigation")
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("task_spec_ib_force_disable")
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtask_1245
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("task_spec_ib_disable")
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtask_1245
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_1.getElse().(IfStmt).getElse().(IfStmt).getElse() instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_1))
}

predicate func_2(Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(BinaryBitwiseOperation).getValue()="2"
		and target_2.getExpr().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getExpr().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(BinaryBitwiseOperation).getValue()="4"
		and target_3.getExpr().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getExpr().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(ReturnStmt target_4 |
		target_4.getExpr().(Literal).getValue()="0"
		and target_4.getEnclosingFunction() = func)
}

predicate func_10(Variable vspectre_v2_user, Parameter vtask_1245, Function func) {
	exists(SwitchStmt target_10 |
		target_10.getExpr().(VariableAccess).getTarget()=vspectre_v2_user
		and target_10.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_10.getStmt().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and target_10.getStmt().(BlockStmt).getStmt(2).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_10.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_10.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("task_spec_ib_force_disable")
		and target_10.getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtask_1245
		and target_10.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_10.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_10.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_10.getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_10.getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("task_spec_ib_disable")
		and target_10.getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtask_1245
		and target_10.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_10.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_10.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_10.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_10.getStmt().(BlockStmt).getStmt(6).(ReturnStmt).getExpr().(BitwiseOrExpr).getValue()="3"
		and target_10.getStmt().(BlockStmt).getStmt(6).(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_10.getStmt().(BlockStmt).getStmt(6).(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_10.getStmt().(BlockStmt).getStmt(6).(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_10.getStmt().(BlockStmt).getStmt(6).(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_10.getStmt().(BlockStmt).getStmt(7).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_10.getStmt().(BlockStmt).getStmt(8).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_10.getStmt().(BlockStmt).getStmt(9) instanceof ReturnStmt
		and target_10.getStmt().(BlockStmt).getStmt(10).(SwitchCase).toString() = "default: "
		and target_10.getStmt().(BlockStmt).getStmt(11) instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

from Function func, Variable vspectre_v2_user, Parameter vtask_1245
where
func_0(vspectre_v2_user)
and not func_1(vtask_1245, func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_10(vspectre_v2_user, vtask_1245, func)
and vtask_1245.getType().hasName("task_struct *")
and not vspectre_v2_user.getParentScope+() = func
and vtask_1245.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
