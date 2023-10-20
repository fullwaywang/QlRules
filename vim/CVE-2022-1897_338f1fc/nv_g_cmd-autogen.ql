/**
 * @name vim-338f1fc0ee3ca929387448fe464579d6113fa76a-nv_g_cmd
 * @id cpp/vim/338f1fc0ee3ca929387448fe464579d6113fa76a/nv-g-cmd
 * @description vim-338f1fc0ee3ca929387448fe464579d6113fa76a-src/normal.c-nv_g_cmd CVE-2022-1897
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("text_locked")
		and not target_0.getTarget().hasName("check_text_locked")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vcap_5883, Variable voap_5885, BlockStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, NotExpr target_2) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("check_text_locked")
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="oap"
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_5883
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("checkclearopq")
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voap_5885
		and target_1.getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable voap_5885, ExprStmt target_13, NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("checkclearopq")
		and target_2.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voap_5885
		and target_2.getParent().(IfStmt).getThen()=target_13
}

predicate func_3(Parameter vcap_5883, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="oap"
		and target_3.getQualifier().(VariableAccess).getTarget()=vcap_5883
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(FunctionCall target_0, Function func, BreakStmt target_4) {
		target_4.toString() = "break;"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_0
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Parameter vcap_5883, FunctionCall target_0, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("clearopbeep")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="oap"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_5883
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_0
}

predicate func_6(FunctionCall target_0, Function func, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("text_locked_msg")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_0
		and target_6.getEnclosingFunction() = func
}

predicate func_7(PointerFieldAccess target_14, Function func, IfStmt target_7) {
		target_7.getCondition() instanceof NotExpr
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("do_exmode")
		and target_7.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_14
		and target_7.getEnclosingFunction() = func
}

predicate func_8(PointerFieldAccess target_14, Function func, BreakStmt target_8) {
		target_8.toString() = "break;"
		and target_8.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_14
		and target_8.getEnclosingFunction() = func
}

predicate func_9(BlockStmt target_9) {
		target_9.getStmt(0) instanceof ExprStmt
		and target_9.getStmt(1) instanceof ExprStmt
		and target_9.getStmt(2) instanceof BreakStmt
}

predicate func_10(Parameter vcap_5883, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("goto_byte")
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="count0"
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_5883
}

predicate func_11(Parameter vcap_5883, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("nv_pcmark")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcap_5883
}

predicate func_12(Parameter vcap_5883, Variable voap_5885, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("do_mouse")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voap_5885
		and target_12.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="nchar"
		and target_12.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_5883
		and target_12.getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_12.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="count1"
		and target_12.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcap_5883
		and target_12.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_13(ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("do_exmode")
		and target_13.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
}

predicate func_14(Parameter vcap_5883, PointerFieldAccess target_14) {
		target_14.getTarget().getName()="nchar"
		and target_14.getQualifier().(VariableAccess).getTarget()=vcap_5883
}

from Function func, Parameter vcap_5883, Variable voap_5885, FunctionCall target_0, NotExpr target_2, PointerFieldAccess target_3, BreakStmt target_4, ExprStmt target_5, ExprStmt target_6, IfStmt target_7, BreakStmt target_8, BlockStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, PointerFieldAccess target_14
where
func_0(func, target_0)
and not func_1(vcap_5883, voap_5885, target_9, target_10, target_11, target_12, target_2)
and func_2(voap_5885, target_13, target_2)
and func_3(vcap_5883, target_3)
and func_4(target_0, func, target_4)
and func_5(vcap_5883, target_0, target_5)
and func_6(target_0, func, target_6)
and func_7(target_14, func, target_7)
and func_8(target_14, func, target_8)
and func_9(target_9)
and func_10(vcap_5883, target_10)
and func_11(vcap_5883, target_11)
and func_12(vcap_5883, voap_5885, target_12)
and func_13(target_13)
and func_14(vcap_5883, target_14)
and vcap_5883.getType().hasName("cmdarg_T *")
and voap_5885.getType().hasName("oparg_T *")
and vcap_5883.getParentScope+() = func
and voap_5885.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
