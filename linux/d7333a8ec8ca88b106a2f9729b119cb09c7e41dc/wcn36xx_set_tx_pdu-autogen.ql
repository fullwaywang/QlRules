/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_set_tx_pdu
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/wcn36xx-set-tx-pdu
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_set_tx_pdu CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbd_313, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="bd_ssn"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_313
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vbd_313
where
func_0(vbd_313, func)
and vbd_313.getType().hasName("wcn36xx_tx_bd *")
and vbd_313.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
