/**
 * @name linux-b4487b93545214a9db8cbf32e86411677b0cca21-_nfs4_get_security_label
 * @id cpp/linux/b4487b93545214a9db8cbf32e86411677b0cca21/_nfs4_get_security_label
 * @description linux-b4487b93545214a9db8cbf32e86411677b0cca21-_nfs4_get_security_label 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuflen_5829, Variable vlabel_5833, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuflen_5829
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="len"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabel_5833
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-34"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="34"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vbuflen_5829, Variable vlabel_5833
where
func_0(vbuflen_5829, vlabel_5833, func)
and vbuflen_5829.getType().hasName("size_t")
and vlabel_5833.getType().hasName("nfs4_label")
and vbuflen_5829.getParentScope+() = func
and vlabel_5833.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
