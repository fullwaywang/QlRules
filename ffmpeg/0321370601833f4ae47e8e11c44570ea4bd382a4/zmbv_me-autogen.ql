/**
 * @name ffmpeg-0321370601833f4ae47e8e11c44570ea4bd382a4-zmbv_me
 * @id cpp/ffmpeg/0321370601833f4ae47e8e11c44570ea4bd382a4/zmbv-me
 * @description ffmpeg-0321370601833f4ae47e8e11c44570ea4bd382a4-libavcodec/zmbvenc.c-zmbv_me CVE-2019-13312
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_99, Variable vmx0_103, ExprStmt target_4, ExprStmt target_5, LogicalOrExpr target_6, ExprStmt target_7) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vmx0_103
		and target_0.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_0.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_99
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(VariableAccess).getLocation())
		and target_0.getLeftOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vc_99, Variable vdx_102, ExprStmt target_8, LogicalAndExpr target_9, ExprStmt target_10) {
	exists(MulExpr target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vdx_102
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_99
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(VariableAccess).getLocation())
		and target_1.getLeftOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_2(Variable vmx0_103, VariableAccess target_2) {
		target_2.getTarget()=vmx0_103
}

predicate func_3(Variable vdx_102, VariableAccess target_3) {
		target_3.getTarget()=vdx_102
}

predicate func_4(Parameter vc_99, Variable vmx0_103, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("block_cmp")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_99
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vmx0_103
}

predicate func_5(Parameter vc_99, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lrange"
		and target_5.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_99
}

predicate func_6(Variable vmx0_103, LogicalOrExpr target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vmx0_103
}

predicate func_7(Variable vmx0_103, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vmx0_103
}

predicate func_8(Parameter vc_99, Variable vdx_102, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("block_cmp")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_99
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdx_102
}

predicate func_9(Variable vdx_102, Variable vmx0_103, LogicalAndExpr target_9) {
		target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdx_102
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vmx0_103
}

predicate func_10(Variable vdx_102, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdx_102
}

from Function func, Parameter vc_99, Variable vdx_102, Variable vmx0_103, VariableAccess target_2, VariableAccess target_3, ExprStmt target_4, ExprStmt target_5, LogicalOrExpr target_6, ExprStmt target_7, ExprStmt target_8, LogicalAndExpr target_9, ExprStmt target_10
where
not func_0(vc_99, vmx0_103, target_4, target_5, target_6, target_7)
and not func_1(vc_99, vdx_102, target_8, target_9, target_10)
and func_2(vmx0_103, target_2)
and func_3(vdx_102, target_3)
and func_4(vc_99, vmx0_103, target_4)
and func_5(vc_99, target_5)
and func_6(vmx0_103, target_6)
and func_7(vmx0_103, target_7)
and func_8(vc_99, vdx_102, target_8)
and func_9(vdx_102, vmx0_103, target_9)
and func_10(vdx_102, target_10)
and vc_99.getType().hasName("ZmbvEncContext *")
and vdx_102.getType().hasName("int")
and vmx0_103.getType().hasName("int")
and vc_99.getParentScope+() = func
and vdx_102.getParentScope+() = func
and vmx0_103.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
