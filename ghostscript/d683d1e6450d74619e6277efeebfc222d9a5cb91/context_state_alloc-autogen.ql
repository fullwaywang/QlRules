/**
 * @name ghostscript-d683d1e6450d74619e6277efeebfc222d9a5cb91-context_state_alloc
 * @id cpp/ghostscript/d683d1e6450d74619e6277efeebfc222d9a5cb91/context-state-alloc
 * @description ghostscript-d683d1e6450d74619e6277efeebfc222d9a5cb91-psi/icontext.c-context_state_alloc CVE-2019-3835
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpcst_115, Function func, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="in_superexec"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcst_115
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Variable vpcst_115, ExprStmt target_0
where
func_0(vpcst_115, func, target_0)
and vpcst_115.getType().hasName("gs_context_state_t *")
and vpcst_115.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
