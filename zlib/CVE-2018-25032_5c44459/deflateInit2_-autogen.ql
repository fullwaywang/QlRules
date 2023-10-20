/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflateInit2_
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflateInit2-
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate.c-deflateInit2_ CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_254, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="l_buf"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_254
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="2"
		and not target_1.getValue()="4"
		and target_1.getParent().(AddExpr).getParent().(ExprCall).getArgument(2) instanceof AddExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_3(Variable vs_254, ExprStmt target_16, ExprStmt target_17) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="sym_end"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_3.getRValue().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_3.getRValue().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_3.getRValue().(MulExpr).getLeftOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_3.getRValue().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vs_254, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="lit_bufsize"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_254
}

predicate func_5(Variable vs_254, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="lit_bufsize"
		and target_5.getQualifier().(VariableAccess).getTarget()=vs_254
}

predicate func_6(Variable vs_254, VariableAccess target_6) {
		target_6.getTarget()=vs_254
}

predicate func_8(Function func, DeclStmt target_8) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Variable vs_254, Variable voverlay_258, Parameter vstrm_0, AssignExpr target_9) {
		target_9.getLValue().(VariableAccess).getTarget()=voverlay_258
		and target_9.getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="zalloc"
		and target_9.getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstrm_0
		and target_9.getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="opaque"
		and target_9.getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstrm_0
		and target_9.getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_9.getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_9.getRValue().(ExprCall).getArgument(2).(AddExpr).getValue()="4"
}

/*predicate func_10(Variable vs_254, Parameter vstrm_0, AddExpr target_10) {
		target_10.getValue()="4"
		and target_10.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="zalloc"
		and target_10.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstrm_0
		and target_10.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="opaque"
		and target_10.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstrm_0
		and target_10.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_10.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
}

*/
predicate func_11(Variable vs_254, Variable voverlay_258, ExprStmt target_19, VariableAccess target_11) {
		target_11.getTarget()=voverlay_258
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pending_buf"
		and target_11.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_11.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_12(Function func, AddExpr target_12) {
		target_12.getValue()="4"
		and target_12.getEnclosingFunction() = func
}

predicate func_13(Variable vs_254, Variable voverlay_258, AssignExpr target_13) {
		target_13.getLValue().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_13.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_13.getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voverlay_258
		and target_13.getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_13.getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_13.getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_13.getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="2"
}

predicate func_14(Variable vs_254, Function func, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="l_buf"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pending_buf"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getValue()="3"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

/*predicate func_15(Variable vs_254, MulExpr target_15) {
		target_15.getLeftOperand().(AddExpr).getValue()="3"
		and target_15.getRightOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_15.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
}

*/
predicate func_16(Variable vs_254, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_16.getExpr().(AssignExpr).getRValue().(Literal).getValue()="666"
}

predicate func_17(Variable vs_254, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="level"
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
}

predicate func_19(Variable vs_254, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pending_buf_size"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_19.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_19.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_19.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand() instanceof AddExpr
}

from Function func, Variable vs_254, Variable voverlay_258, Parameter vstrm_0, PointerFieldAccess target_0, Literal target_1, PointerFieldAccess target_4, PointerFieldAccess target_5, VariableAccess target_6, DeclStmt target_8, AssignExpr target_9, VariableAccess target_11, AddExpr target_12, AssignExpr target_13, ExprStmt target_14, ExprStmt target_16, ExprStmt target_17, ExprStmt target_19
where
func_0(vs_254, target_0)
and func_1(func, target_1)
and not func_3(vs_254, target_16, target_17)
and func_4(vs_254, target_4)
and func_5(vs_254, target_5)
and func_6(vs_254, target_6)
and func_8(func, target_8)
and func_9(vs_254, voverlay_258, vstrm_0, target_9)
and func_11(vs_254, voverlay_258, target_19, target_11)
and func_12(func, target_12)
and func_13(vs_254, voverlay_258, target_13)
and func_14(vs_254, func, target_14)
and func_16(vs_254, target_16)
and func_17(vs_254, target_17)
and func_19(vs_254, target_19)
and vs_254.getType().hasName("deflate_state *")
and voverlay_258.getType().hasName("ushf *")
and vstrm_0.getType().hasName("z_streamp")
and vs_254.getParentScope+() = func
and voverlay_258.getParentScope+() = func
and vstrm_0.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
