/**
 * @name linux-a4176ec356c73a46c07c181c6d04039fafa34a9f-brcmf_rx_frame
 * @id cpp/linux/a4176ec356c73a46c07c181c6d04039fafa34a9f/brcmf-rx-frame
 * @description linux-a4176ec356c73a46c07c181c6d04039fafa34a9f-brcmf_rx_frame NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="32769"
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
