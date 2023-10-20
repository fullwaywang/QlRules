/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflateCopy
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflateCopy
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate.c-deflateCopy CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vds_1114, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="l_buf"
		and target_0.getQualifier().(VariableAccess).getTarget()=vds_1114
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="2"
		and not target_1.getValue()="4"
		and target_1.getParent().(AddExpr).getParent().(ExprCall).getArgument(2) instanceof AddExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vds_1114, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="lit_bufsize"
		and target_2.getQualifier().(VariableAccess).getTarget()=vds_1114
}

predicate func_3(Function func, DeclStmt target_3) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Parameter vdest_0, Variable vds_1114, Variable voverlay_1116, AssignExpr target_4) {
		target_4.getLValue().(VariableAccess).getTarget()=voverlay_1116
		and target_4.getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="zalloc"
		and target_4.getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_0
		and target_4.getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="opaque"
		and target_4.getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_0
		and target_4.getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_4.getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_4.getRValue().(ExprCall).getArgument(2).(AddExpr).getValue()="4"
}

/*predicate func_5(Parameter vdest_0, Variable vds_1114, AddExpr target_5) {
		target_5.getValue()="4"
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="zalloc"
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_0
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="opaque"
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_0
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
}

*/
predicate func_6(Variable vds_1114, Variable voverlay_1116, LogicalOrExpr target_11, ExprStmt target_7, VariableAccess target_6) {
		target_6.getTarget()=voverlay_1116
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pending_buf"
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
}

predicate func_7(Variable vds_1114, Variable voverlay_1116, Function func, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voverlay_1116
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="2"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vds_1114, Function func, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="l_buf"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pending_buf"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getValue()="3"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

/*predicate func_9(Variable vds_1114, MulExpr target_9) {
		target_9.getLeftOperand().(AddExpr).getValue()="3"
		and target_9.getRightOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_9.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
}

*/
predicate func_11(Variable vds_1114, LogicalOrExpr target_11) {
		target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="window"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="prev"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="head"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pending_buf"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vdest_0, Variable vds_1114, Variable voverlay_1116, PointerFieldAccess target_0, Literal target_1, PointerFieldAccess target_2, DeclStmt target_3, AssignExpr target_4, VariableAccess target_6, ExprStmt target_7, ExprStmt target_8, LogicalOrExpr target_11
where
func_0(vds_1114, target_0)
and func_1(func, target_1)
and func_2(vds_1114, target_2)
and func_3(func, target_3)
and func_4(vdest_0, vds_1114, voverlay_1116, target_4)
and func_6(vds_1114, voverlay_1116, target_11, target_7, target_6)
and func_7(vds_1114, voverlay_1116, func, target_7)
and func_8(vds_1114, func, target_8)
and func_11(vds_1114, target_11)
and vdest_0.getType().hasName("z_streamp")
and vds_1114.getType().hasName("deflate_state *")
and voverlay_1116.getType().hasName("ushf *")
and vdest_0.getParentScope+() = func
and vds_1114.getParentScope+() = func
and voverlay_1116.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
