export default function homeController(req, res) {
    res.render('home', {
        metaTitle: 'Stateless Authentication Example | Home'
    });
}
