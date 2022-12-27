/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflateCopy
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflateCopy
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflateCopy CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vds_1114) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="l_buf"
		and target_0.getQualifier().(VariableAccess).getTarget()=vds_1114)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="2"
		and not target_1.getValue()="4"
		and target_1.getParent().(AddExpr).getParent().(ExprCall).getArgument(2) instanceof AddExpr
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vds_1114) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="lit_bufsize"
		and target_2.getQualifier().(VariableAccess).getTarget()=vds_1114)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Parameter vdest_0, Variable vds_1114, Variable voverlay_1116) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=voverlay_1116
		and target_4.getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="zalloc"
		and target_4.getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_0
		and target_4.getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="opaque"
		and target_4.getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_0
		and target_4.getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_4.getRValue().(ExprCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_4.getRValue().(ExprCall).getArgument(2).(AddExpr).getValue()="4")
}

predicate func_6(Variable vds_1114, Variable voverlay_1116) {
	exists(VariableAccess target_6 |
		target_6.getTarget()=voverlay_1116
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pending_buf"
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114)
}

predicate func_7(Variable vds_1114, Variable voverlay_1116, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voverlay_1116
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getLeftOperand() instanceof PointerFieldAccess
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="2"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Variable vds_1114, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue() instanceof PointerFieldAccess
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pending_buf"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="2"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vds_1114
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

from Function func, Parameter vdest_0, Variable vds_1114, Variable voverlay_1116
where
func_0(vds_1114)
and func_1(func)
and func_2(vds_1114)
and func_3(func)
and func_4(vdest_0, vds_1114, voverlay_1116)
and func_6(vds_1114, voverlay_1116)
and func_7(vds_1114, voverlay_1116, func)
and func_8(vds_1114, func)
and vdest_0.getType().hasName("z_streamp")
and vds_1114.getType().hasName("deflate_state *")
and voverlay_1116.getType().hasName("ushf *")
and vdest_0.getParentScope+() = func
and vds_1114.getParentScope+() = func
and voverlay_1116.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
