// 主JavaScript文件
document.addEventListener('DOMContentLoaded', function() {
    // 详情链接处理 - 在新窗口打开
    const detailLinks = document.querySelectorAll('.detail-link');
    detailLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const url = this.getAttribute('href');
            window.open(url, '_blank');
        });
    });

    // 过滤按钮切换样式
    const filterButtons = document.querySelectorAll('.source-filter');
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            filterButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
        });
    });

    // 移动端菜单切换
    const navbarToggler = document.querySelector('.navbar-toggler');
    if (navbarToggler) {
        navbarToggler.addEventListener('click', function() {
            const navCollapse = document.querySelector('.navbar-collapse');
            navCollapse.classList.toggle('show');
        });
    }
}); 