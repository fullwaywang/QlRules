/**
 * @name linux-36e4ad0316c017d5b271378ed9a1c9a4b77fab5f-read_rindex_entry
 * @id cpp/linux/36e4ad0316c017d5b271378ed9a1c9a4b77fab5f/read-rindex-entry
 * @description linux-36e4ad0316c017d5b271378ed9a1c9a4b77fab5f-read_rindex_entry NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrgd_886, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rd_bits"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrgd_886
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(34)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(34).getFollowingStmt()=target_0))
}

predicate func_1(Variable vrgd_886, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gl_object"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_gl"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrgd_886
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vrgd_886
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vbsize_882, Variable vrgd_886, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="start"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="gl_vm"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_gl"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrgd_886
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="rd_addr"
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrgd_886
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbsize_882
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="18446744073709547520"
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vbsize_882, Variable vrgd_886, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="end"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="gl_vm"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_gl"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrgd_886
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="rd_addr"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrgd_886
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="rd_length"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrgd_886
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbsize_882
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Variable verror_885) {
	exists(ReturnStmt target_4 |
		target_4.getExpr().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=verror_885)
}

predicate func_5(Variable vrgd_886) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("rgd_insert")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vrgd_886)
}

from Function func, Variable vbsize_882, Variable verror_885, Variable vrgd_886
where
not func_0(vrgd_886, func)
and func_1(vrgd_886, func)
and func_2(vbsize_882, vrgd_886, func)
and func_3(vbsize_882, vrgd_886, func)
and func_4(verror_885)
and vbsize_882.getType().hasName("const unsigned int")
and verror_885.getType().hasName("int")
and vrgd_886.getType().hasName("gfs2_rgrpd *")
and func_5(vrgd_886)
and vbsize_882.getParentScope+() = func
and verror_885.getParentScope+() = func
and vrgd_886.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
