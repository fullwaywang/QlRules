/**
 * @name linux-401e7e88d4ef80188ffa07095ac00456f901b8c4-try_smi_init
 * @id cpp/linux/401e7e88d4ef80188ffa07095ac00456f901b8c4/try_smi_init
 * @description linux-401e7e88d4ef80188ffa07095ac00456f901b8c4-try_smi_init 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vnew_smi_1921, Variable vrv_1923, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vrv_1923
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="io_cleanup"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="io"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_smi_1921
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="io_cleanup"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="io"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_smi_1921
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="io"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_smi_1921
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="io_cleanup"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="io"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_smi_1921
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(41)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(41).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vnew_smi_1921) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="io"
		and target_3.getQualifier().(VariableAccess).getTarget()=vnew_smi_1921)
}

predicate func_4(Parameter vnew_smi_1921, Variable vrv_1923) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("_dev_err")
		and target_4.getArgument(0).(ValueFieldAccess).getTarget().getName()="dev"
		and target_4.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="io"
		and target_4.getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_smi_1921
		and target_4.getArgument(1).(StringLiteral).getValue()="Unable to register device: error %d\n"
		and target_4.getArgument(2).(VariableAccess).getTarget()=vrv_1923)
}

from Function func, Parameter vnew_smi_1921, Variable vrv_1923
where
not func_0(vnew_smi_1921, vrv_1923, func)
and vnew_smi_1921.getType().hasName("smi_info *")
and func_3(vnew_smi_1921)
and vrv_1923.getType().hasName("int")
and func_4(vnew_smi_1921, vrv_1923)
and vnew_smi_1921.getParentScope+() = func
and vrv_1923.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
