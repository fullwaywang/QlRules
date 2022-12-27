/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflateInit2_
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflateInit2-
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflateInit2_ CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_254) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="l_buf"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_254)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="2"
		and not target_1.getValue()="4"
		and target_1.getParent().(AddExpr).getParent().(ExprCall).getArgument(2) instanceof AddExpr
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Variable vs_254) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="sym_end"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_3.getRValue().(MulExpr).getLeftOperand().(SubExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_3.getRValue().(MulExpr).getLeftOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_3.getRValue().(MulExpr).getRightOperand().(Literal).getValue()="3")
}

predicate func_4(Variable vs_254) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="lit_bufsize"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_254)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="1"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(DeclStmt target_8 |
		target_8.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_9(Variable vs_254, Variable voverlay_258, Parameter vstrm_0) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=voverlay_258
		and target_9.getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="zalloc"
		and target_9.getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstrm_0
		and target_9.getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="opaque"
		and target_9.getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstrm_0
		and target_9.getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_9.getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_9.getRValue().(ExprCall).getArgument(2).(AddExpr).getValue()="4")
}

predicate func_11(Variable vs_254, Variable voverlay_258) {
	exists(VariableAccess target_11 |
		target_11.getTarget()=voverlay_258
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pending_buf"
		and target_11.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254)
}

predicate func_12(Function func) {
	exists(AddExpr target_12 |
		target_12.getValue()="4"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Variable vs_254, Variable voverlay_258) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_13.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_13.getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voverlay_258
		and target_13.getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_13.getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_13.getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="2")
}

predicate func_14(Variable vs_254, Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(AssignExpr).getLValue() instanceof PointerFieldAccess
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pending_buf"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_254
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="2"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand() instanceof PointerFieldAccess
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14)
}

from Function func, Variable vs_254, Variable voverlay_258, Parameter vstrm_0
where
func_0(vs_254)
and func_1(func)
and not func_3(vs_254)
and func_4(vs_254)
and func_7(func)
and func_8(func)
and func_9(vs_254, voverlay_258, vstrm_0)
and func_11(vs_254, voverlay_258)
and func_12(func)
and func_13(vs_254, voverlay_258)
and func_14(vs_254, func)
and vs_254.getType().hasName("deflate_state *")
and voverlay_258.getType().hasName("ushf *")
and vstrm_0.getType().hasName("z_streamp")
and vs_254.getParentScope+() = func
and voverlay_258.getParentScope+() = func
and vstrm_0.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
