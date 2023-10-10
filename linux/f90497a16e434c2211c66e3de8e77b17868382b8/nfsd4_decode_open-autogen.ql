/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_open
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-open
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_open 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vopen_1138) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="12"
		and target_0.getExprOperand().(PointerFieldAccess).getTarget().getName()="op_bmval"
		and target_0.getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopen_1138)
}

predicate func_1(Parameter vopen_1138) {
	exists(PointerDereferenceExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vopen_1138)
}

predicate func_4(Parameter vopen_1138) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="op_bmval"
		and target_4.getQualifier().(VariableAccess).getTarget()=vopen_1138)
}

predicate func_5(Parameter vopen_1138, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ia_valid"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_iattr"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopen_1138
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Parameter vopen_1138, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="op_openowner"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopen_1138
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_7(Parameter vopen_1138, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="op_xdr_error"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopen_1138
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

from Function func, Parameter vopen_1138
where
func_0(vopen_1138)
and not func_1(vopen_1138)
and func_4(vopen_1138)
and func_5(vopen_1138, func)
and func_6(vopen_1138, func)
and func_7(vopen_1138, func)
and vopen_1138.getType().hasName("nfsd4_open *")
and vopen_1138.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
