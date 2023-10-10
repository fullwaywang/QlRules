/**
 * @name linux-c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d-snd_rawmidi_kernel_read1
 * @id cpp/linux/c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d/snd_rawmidi_kernel_read1
 * @description linux-c1f6e3c818dd734c30f6a7eeebf232ba2cf3181d-snd_rawmidi_kernel_read1 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_0)
}

predicate func_1(Variable vruntime_1020, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("snd_rawmidi_buffer_ref")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vruntime_1020
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vuserbuf_1015, Variable vresult_1019, Variable vcount1_1019, Variable vruntime_1020, Variable vappl_ptr_1021) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue() instanceof UnaryMinusExpr
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("copy_to_user")
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vuserbuf_1015
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vresult_1019
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer"
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_1020
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vappl_ptr_1021
		and target_2.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcount1_1019)
}

predicate func_3(Parameter vuserbuf_1015) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getType().hasName("int")
		and target_3.getThen().(GotoStmt).toString() = "goto ..."
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vuserbuf_1015)
}

predicate func_4(Function func) {
	exists(LabelStmt target_4 |
		target_4.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_4))
}

predicate func_5(Variable vruntime_1020, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("snd_rawmidi_buffer_unref")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vruntime_1020
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_5))
}

predicate func_7(Function func) {
	exists(UnaryMinusExpr target_7 |
		target_7.getValue()="-14"
		and target_7.getOperand().(Literal).getValue()="14"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Parameter vuserbuf_1015, Variable vresult_1019, Variable vcount1_1019, Variable vruntime_1020, Variable vappl_ptr_1021) {
	exists(ReturnStmt target_8 |
		target_8.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vresult_1019
		and target_8.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_8.getExpr().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vresult_1019
		and target_8.getExpr().(ConditionalExpr).getElse() instanceof UnaryMinusExpr
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("copy_to_user")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vuserbuf_1015
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vresult_1019
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vruntime_1020
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vappl_ptr_1021
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcount1_1019)
}

predicate func_9(Variable vresult_1019) {
	exists(VariableAccess target_9 |
		target_9.getTarget()=vresult_1019)
}

predicate func_10(Variable vruntime_1020) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="lock"
		and target_10.getQualifier().(VariableAccess).getTarget()=vruntime_1020)
}

from Function func, Parameter vuserbuf_1015, Variable vresult_1019, Variable vcount1_1019, Variable vruntime_1020, Variable vappl_ptr_1021
where
not func_0(func)
and not func_1(vruntime_1020, func)
and not func_2(vuserbuf_1015, vresult_1019, vcount1_1019, vruntime_1020, vappl_ptr_1021)
and not func_3(vuserbuf_1015)
and not func_4(func)
and not func_5(vruntime_1020, func)
and func_7(func)
and func_8(vuserbuf_1015, vresult_1019, vcount1_1019, vruntime_1020, vappl_ptr_1021)
and func_9(vresult_1019)
and vuserbuf_1015.getType().hasName("unsigned char *")
and vresult_1019.getType().hasName("long")
and vcount1_1019.getType().hasName("long")
and vruntime_1020.getType().hasName("snd_rawmidi_runtime *")
and func_10(vruntime_1020)
and vappl_ptr_1021.getType().hasName("unsigned long")
and vuserbuf_1015.getParentScope+() = func
and vresult_1019.getParentScope+() = func
and vcount1_1019.getParentScope+() = func
and vruntime_1020.getParentScope+() = func
and vappl_ptr_1021.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
